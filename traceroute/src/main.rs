use anyhow::anyhow;
use pnet::packet::{
    icmp::{echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::MutableUdpPacket,
    Packet,
};
use raw_socket::{
    option::{Level, Name},
    tokio::RawSocket,
    {Domain, Protocol, Type},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use structopt::StructOpt;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, Semaphore,
    },
    time::{timeout, Duration, Instant},
};

const START_TTL: u8 = 0;
const MAX_TASKS_IN_FLIGHT: usize = 4;
const IP_HDR_LEN: usize = 20;
const ICMP_HDR_LEN: usize = 8;
const UDP_HDR_LEN: usize = 8;
const TRACEROUTE_PORT: usize = 33434;
const IPPROTO_RAW: i32 = 255;

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let result = run(&opt.target, &opt.protocol).await;

    if let Err(e) = result {
        eprintln!("traceroute error: {:?}", e);
    }
}

async fn run(target: &str, protocol: &str) -> anyhow::Result<()> {
    let target_ip = to_ipaddr(target)?;
    let protocol = TracerouteProtocol::from_str(protocol)?;

    let semaphore = Arc::new(Semaphore::new(MAX_TASKS_IN_FLIGHT));

    /* Protected access to these variables that are shared across the tasks is needed
     * to synchronize them and prevent race conditions, by e.g. having two tasks updating
     * the TTL simultaneously. */
    let ttl_mutex = Arc::new(Mutex::new(START_TTL));
    let times_mutex = Arc::new(Mutex::new(HashMap::new()));
    let probed_mutex = Arc::new(Mutex::new(HashSet::new()));

    /* Memory channel for communicating between the printer and the receiver. */
    let (tx, rx) = channel(8192);

    let printer = tokio::spawn(print_results(rx));
    let receiver = tokio::spawn(receive(
        Arc::clone(&semaphore),
        Arc::clone(&times_mutex),
        tx.clone(),
        Arc::clone(&ttl_mutex),
        Arc::clone(&probed_mutex),
    ));

    let mut tasks = vec![];

    for _ in 0..255 {
        let target_ip = target_ip.clone();
        let semaphore = Arc::clone(&semaphore);
        let counter_mutex = Arc::clone(&ttl_mutex);
        let times_mutex = Arc::clone(&times_mutex);
        let probed_mutex = Arc::clone(&probed_mutex);

        tasks.push(tokio::spawn(trace(
            target_ip,
            protocol,
            semaphore,
            counter_mutex,
            times_mutex,
            probed_mutex,
        )));
    }

    for task in tasks {
        let _ = task.await?;
    }

    let _ = printer.await?;
    let _ = receiver.await?;

    Ok(())
}

async fn trace(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    semaphore: Arc<Semaphore>,
    counter_mutex: Arc<Mutex<u8>>,
    times_mutex: Arc<Mutex<HashMap<usize, Instant>>>,
    probed_mutex: Arc<Mutex<HashSet<u8>>>,
) -> anyhow::Result<()> {
    /* Allow no more than MAX_TASKS_IN_FLIGHT tasks to run concurrently.
     * We are limiting the number of tasks in flight so we don't end up
     * sending more packets than needed by spawning too many tasks. */
    if let Ok(permit) = semaphore.clone().acquire().await {
        /* Each task increments the TTL and sends a probe. */
        let ttl = {
            let mut counter = counter_mutex.lock().await;
            *counter += 1;
            *counter
        };

        {
            let mut probed = probed_mutex.lock().await;
            probed.insert(ttl);    
        }

        send_probe(target, protocol, ttl, Arc::clone(&times_mutex)).await?;
    
        permit.forget();
    }
    Ok(())
}

async fn send_probe(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    ttl: u8,
    times_mutex: Arc<Mutex<HashMap<usize, Instant>>>,
) -> std::io::Result<()> {
    let sock = RawSocket::new(
        Domain::ipv4(),
        Type::raw(),
        Protocol::from(IPPROTO_RAW).into(),
    )?;

    let ip_next_hdr_protocol = match protocol {
        TracerouteProtocol::Udp => IpNextHeaderProtocols::Udp,
        TracerouteProtocol::Icmp => IpNextHeaderProtocols::Icmp,
    };

    let ip_next_hdr_len = match protocol {
        TracerouteProtocol::Udp => UDP_HDR_LEN,
        TracerouteProtocol::Icmp => ICMP_HDR_LEN,
    };

    let mut ipv4_buf = match protocol {
        TracerouteProtocol::Udp => vec![0u8; IP_HDR_LEN + UDP_HDR_LEN],
        TracerouteProtocol::Icmp => vec![0u8; IP_HDR_LEN + ICMP_HDR_LEN],
    };

    let mut ip_next_hdr_buf = match protocol {
        TracerouteProtocol::Udp => vec![0u8; UDP_HDR_LEN],
        TracerouteProtocol::Icmp => vec![0u8; ICMP_HDR_LEN],
    };

    let mut ipv4_packet = build_ipv4_packet(
        &mut ipv4_buf,
        target,
        (IP_HDR_LEN + ip_next_hdr_len) as u16,
        ttl,
        ip_next_hdr_protocol,
    );
    let next_packet = match protocol {
        TracerouteProtocol::Udp => build_udp_packet(&mut ip_next_hdr_buf),
        TracerouteProtocol::Icmp => build_icmp_packet(&mut ip_next_hdr_buf),
    };

    match next_packet {
        NextPacket::Icmp(packet) => ipv4_packet.set_payload(packet.packet()),
        NextPacket::Udp(packet) => ipv4_packet.set_payload(packet.packet()),
    };

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &(1i32))?;
    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &i32::from(ttl))?;
    sock.send_to(ipv4_packet.packet(), (target, 0)).await?;

    let mut times = {
        let guard = times_mutex.lock().await;
        guard
    };
    times.insert(ttl.into(), Instant::now());

    Ok(())
}

async fn receive(
    semaphore: Arc<Semaphore>,
    times_mutex: Arc<Mutex<HashMap<usize, Instant>>>,
    tx: Sender<Message>,
    counter_mutex: Arc<Mutex<u8>>,
    probed_mutex: Arc<Mutex<HashSet<u8>>>,
) -> anyhow::Result<()> {
    let recv_sock = create_sock()?;
    let mut recv_buf = [0u8; 16536];

    let mut recvd = HashSet::new();

    loop {
        let (_bytes_received, ip_addr) =
        match timeout(Duration::from_secs(1), recv_sock.recv_from(&mut recv_buf)).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                let ttl = {
                    let guard = counter_mutex.lock().await;
                    *guard
                };
                tx.send(Message::Timeout(ttl)).await?;
                println!("sent timeout, returnin Err");
                return Err(anyhow!("We timed out."));
            }
        };

        let icmp_packet = match IcmpPacket::new(&recv_buf[IP_HDR_LEN..]) {
            Some(packet) => packet,
            None => return Err(anyhow!("Couldn't make an ICMP packet.")),
        };

        let reverse_dns_task =
            tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr.clone().ip()));
        let hostname = match reverse_dns_task.await? {
            Ok(host) => host,
            Err(e) => return Err(anyhow!("Reverse DNS failed: {:?}", e)),
        };

        let original_ipv4_packet =
        match Ipv4Packet::new(&recv_buf[IP_HDR_LEN + ICMP_HDR_LEN..]) {
            Some(packet) => packet,
            None => return Err(anyhow!("Couldn't make an IPv4 packet.")),
        };
        let hop = original_ipv4_packet.get_identification();

        recvd.insert(hop as u8);

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                /* A part of the original IPv4 packet (header + at least first 8 bytes)
                    * is contained in an ICMP error message. We use the identification field
                    * to map responses back to correct hops. */
   
                let guard = times_mutex.lock().await;

                let time_elapsed =
                    Instant::now().duration_since(*guard.get(&(hop as usize)).unwrap());

                tx.send(Message::Ok((hop as u8, hostname, ip_addr, time_elapsed)))
                    .await?;

                /* Allow one more task to go through. */
                semaphore.add_permits(1);
            }
            IcmpTypes::EchoReply | IcmpTypes::DestinationUnreachable => {
                let times = {
                    let guard = times_mutex.lock().await;
                    guard
                };
                let time_elapsed =
                    Instant::now().duration_since(*times.get(&(hop as usize)).unwrap());

                tx.send(Message::Ok((hop as u8, hostname, ip_addr, time_elapsed)))
                    .await?;

                {
                    let probed = probed_mutex.lock().await;
                    let diff = (*probed).difference(&recvd);

                    for d in diff {
                        if *d < hop as u8 {
                            tx.send(Message::Timeout(*d)).await?;
                        }
                    }
                }
            
                semaphore.close();

                tx.send(Message::Quit).await?;

                break;
            }
            _ => {}
        }

    }

    Ok(())
}

#[derive(Debug, Clone)]
enum Response {
    WillArrive(u8, String, SocketAddr, Duration),
    WontArrive(u8),
}

async fn print_results(mut rx: Receiver<Message>) {
    /* The printer awaits messages from the receiver. Sometimes, the messages
     * arrive out of order, so the printer's job is to sort that out and print
     * the hops in ascending order. */
     let mut responses: [Option<Response>; 255] = std::iter::repeat(None)
        .take(255)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut printed = 0;

    while let Some(msg) = rx.recv().await {
        match msg {
            Message::Ok((hop, hostname, ip_addr, time)) => {
                responses[hop as usize - 1] = Some(Response::WillArrive(hop, hostname.clone(), ip_addr, time));
            }
            Message::Timeout(hop) => {
                responses[hop as usize - 1] = Some(Response::WontArrive(hop));
            }
            Message::Quit => break,
        }

        while printed < 255 && !responses[printed].is_none() {
            if let Some(response) = responses[printed].clone() {
                match response.clone() {
                    Response::WontArrive(hop) => {
                        println!("{}:  *** ", hop);
                        printed += 1;
                    }
                    Response::WillArrive(hop, hostname, ip_addr, time) => {
                        println!("{}: {} ({}) - {:?}", hop, hostname, ip_addr, time);
                        printed += 1;
                    }
                }
            }
        }

    }
}
fn build_ipv4_packet(
    buf: &mut [u8],
    dest: Ipv4Addr,
    size: u16,
    ttl: u8,
    next_header: IpNextHeaderProtocol,
) -> MutableIpv4Packet {
    use pnet::packet::ipv4::checksum;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();

    packet.set_version(4);
    packet.set_ttl(ttl);
    packet.set_header_length(5); /* n * 32 bits. */

    /* We are setting the identification field to the TTL
     * that we later use to map responses back to correct hops. */
    packet.set_identification(ttl as u16);
    packet.set_next_level_protocol(next_header);
    packet.set_destination(dest);
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_total_length(size);
    packet.set_checksum(checksum(&packet.to_immutable()));

    packet
}

fn build_icmp_packet(buf: &mut [u8]) -> NextPacket {
    use pnet::packet::icmp::checksum;

    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();
    let seq_no = rand::random::<u16>();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_sequence_number(seq_no);
    packet.set_identifier(0x1337);
    packet.set_checksum(checksum(&IcmpPacket::new(packet.packet()).unwrap()));

    NextPacket::Icmp(packet)
}

fn build_udp_packet(buf: &mut [u8]) -> NextPacket {
    let mut packet = MutableUdpPacket::new(buf).unwrap();

    packet.set_source(TRACEROUTE_PORT as u16);
    packet.set_destination(TRACEROUTE_PORT as u16);
    packet.set_length(UDP_HDR_LEN as u16);
    packet.set_checksum(0);

    NextPacket::Udp(packet)
}

fn to_ipaddr(target: &str) -> anyhow::Result<Ipv4Addr> {
    match target.parse::<Ipv4Addr>() {
        Ok(addr) => Ok(addr),
        Err(_) => match dns_lookup::lookup_host(target) {
            Ok(ip_addrs) => match ip_addrs[0] {
                IpAddr::V4(addr) => Ok(addr),
                IpAddr::V6(_) => return Err(anyhow!("Not implemented for IPv6.")),
            },
            Err(_) => return Err(anyhow!("Couldn't resolve the hostname to IP.")),
        },
    }
}

fn create_sock() -> anyhow::Result<Arc<RawSocket>> {
    match RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()) {
        Ok(sock) => Ok(Arc::new(sock)),
        Err(_) => return Err(anyhow!("Couldn't create the socket.")),
    }
}

enum NextPacket<'a> {
    Udp(MutableUdpPacket<'a>),
    Icmp(MutableEchoRequestPacket<'a>),
}

#[derive(Copy, Clone)]
enum TracerouteProtocol {
    Icmp,
    Udp,
}

impl TracerouteProtocol {
    fn from_str(protocol: &str) -> anyhow::Result<Self> {
        match protocol {
            "icmp" => Ok(TracerouteProtocol::Icmp),
            "udp" => Ok(TracerouteProtocol::Udp),
            _ => Err(anyhow!("Protocol not recognized.")),
        }
    }
}

#[derive(Debug)]
enum Message {
    Ok((u8, String, SocketAddr, Duration)),
    Timeout(u8),
    Quit,
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short = "p", long = "protocol", default_value="icmp"]]
    protocol: String,
}
