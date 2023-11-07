use anyhow::{bail, Result};
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
    str::FromStr,
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
        eprintln!("traceroute: {}", e);
    }
}

async fn run(target: &str, protocol: &str) -> Result<()> {
    let target_ip = to_ipaddr(target)?;
    let protocol = protocol.parse::<TracerouteProtocol>()?;

    let semaphore = Arc::new(Semaphore::new(MAX_TASKS_IN_FLIGHT));

    /* Protected access to these variables that are shared across the tasks is needed
     * to synchronize them and prevent race conditions, by e.g. having two tasks updating
     * the TTL simultaneously. */
    let ttl = Arc::new(Mutex::new(START_TTL));
    let timetable = Arc::new(Mutex::new(HashMap::new()));
    let wont_be_coming = Arc::new(Mutex::new(HashSet::new()));

    /* Memory channel for communicating between the printer and the receiver. */
    let (tx, rx) = channel(8192);

    let printer = tokio::spawn(print_results(rx, semaphore.clone()));

    let mut tasks = vec![];

    for _ in 0..u8::MAX {
        tasks.push(tokio::spawn(trace(
            target_ip,
            protocol,
            semaphore.clone(),
            ttl.clone(),
            timetable.clone(),
            tx.clone(),
            wont_be_coming.clone(),
        )));
    }

    for task in tasks {
        task.await??;
    }

    printer.await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn trace(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    semaphore: Arc<Semaphore>,
    ttl: Arc<Mutex<u8>>,
    timetable: Arc<Mutex<HashMap<u8, Instant>>>,
    tx: Sender<Message>,
    wont_be_coming: Arc<Mutex<HashSet<u8>>>,
) -> Result<()> {
    /* Allow no more than MAX_TASKS_IN_FLIGHT tasks to run concurrently.
     * We are limiting the number of tasks in flight so we don't end up
     * sending more packets than needed by spawning too many tasks. */

    if let Ok(permit) = semaphore.acquire().await {
        /* Each task increments the TTL and sends a probe. */
        let ttl = {
            let mut counter = ttl.lock().await;
            *counter += 1;
            *counter
        };

        for _ in 0..3 {
            send_probe(target, protocol, ttl, timetable.clone()).await?;
        }
        receive(
            semaphore.clone(),
            timetable.clone(),
            ttl,
            tx.clone(),
            wont_be_coming.clone(),
        )
        .await?;

        permit.forget();
    }

    Ok(())
}

async fn send_probe(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    ttl: u8,
    timetable: Arc<Mutex<HashMap<u8, Instant>>>,
) -> Result<()> {
    let sock = RawSocket::new(
        Domain::ipv4(),
        Type::raw(),
        Protocol::from(IPPROTO_RAW).into(),
    )?;

    let (ip_next_hdr_protocol, ip_next_hdr_len, mut ipv4_buf, mut ip_next_hdr_buf) = match protocol
    {
        TracerouteProtocol::Udp => (
            IpNextHeaderProtocols::Udp,
            UDP_HDR_LEN,
            vec![0u8; IP_HDR_LEN + UDP_HDR_LEN],
            vec![0u8; UDP_HDR_LEN],
        ),
        TracerouteProtocol::Icmp => (
            IpNextHeaderProtocols::Icmp,
            ICMP_HDR_LEN,
            vec![0u8; IP_HDR_LEN + ICMP_HDR_LEN],
            vec![0u8; ICMP_HDR_LEN],
        ),
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

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &1i32)?;
    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &i32::from(ttl))?;
    sock.send_to(ipv4_packet.packet(), (target, 33434)).await?;

    timetable.lock().await.insert(ttl, Instant::now());

    Ok(())
}

async fn receive(
    semaphore: Arc<Semaphore>,
    timetable: Arc<Mutex<HashMap<u8, Instant>>>,
    ttl: u8,
    tx: Sender<Message>,
    wont_be_coming: Arc<Mutex<HashSet<u8>>>,
) -> Result<()> {
    let recv_sock = create_sock()?;
    let mut recv_buf = [0u8; 65536];
    let mut hop = 0;
    let mut icmp_packet_opt = None;
    let mut ip_addr_opt = None;

    while hop != ttl {
        let (_bytes_received, ip_addr) =
            match timeout(Duration::from_secs(3), recv_sock.recv_from(&mut recv_buf)).await {
                Ok(result) => result.unwrap(),
                Err(_) => {
                    println!("sending Timeout for {}", ttl);
                    tx.send(Message::Timeout(ttl)).await?;
                    wont_be_coming.lock().await.insert(ttl);
                    return Ok(());
                }
            };

        ip_addr_opt = Some(ip_addr);

        icmp_packet_opt = match IcmpPacket::new(&recv_buf[IP_HDR_LEN..]) {
            Some(packet) => Some(packet),
            None => bail!("couldn't make icmp packet"),
        };

        if let Some(ref packet) = icmp_packet_opt {
            if packet.get_icmp_type() == IcmpTypes::EchoReply {
                /* For some reason, on EchoReply, hop is zero. */
                hop = ttl;
                break;
            }
        }

        let original_ipv4_packet = match Ipv4Packet::new(&recv_buf[IP_HDR_LEN + ICMP_HDR_LEN..]) {
            Some(packet) => packet,
            None => bail!("couldn't make ivp4 packet"),
        };

        hop = original_ipv4_packet.get_identification() as u8;
    }

    let icmp_packet = icmp_packet_opt.unwrap();
    let ip_addr = ip_addr_opt.unwrap();

    let reverse_dns_task =
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_addr.ip()));

    let hostname = reverse_dns_task.await??;

    match icmp_packet.get_icmp_type() {
        IcmpTypes::TimeExceeded => {
            /* A part of the original IPv4 packet (header + at least first 8 bytes)
             * is contained in an ICMP error message. We use the identification fi-
             * eld to map responses back to correct hops. */

            let rtt = time_for_hop(&timetable, hop).await?;

            let _ = tx.send(Message::Ok(hop, hostname, ip_addr, rtt)).await;

            /* Allow one more task to go through. */
            semaphore.add_permits(1);
        }
        IcmpTypes::EchoReply => {
            let rtt = time_for_hop(&timetable, hop).await?;

            let _ = tx
                .send(Message::EchoReply(hop, hostname, ip_addr, rtt))
                .await;
        }
        IcmpTypes::DestinationUnreachable => {
            let rtt = time_for_hop(&timetable, hop).await?;
            let code = icmp_packet.get_icmp_code();

            let _ = tx
                .send(Message::DestinationUnreachable(
                    hop, hostname, ip_addr, rtt, code,
                ))
                .await;
        }
        _ => {}
    }

    Ok(())
}

async fn print_results(mut rx: Receiver<Message>, semaphore: Arc<Semaphore>) {
    /* The printer awaits messages from the receiver. Sometimetable, the messages
     * arrive out of order, so the printer's job is to sort that out and print
     * the hops in ascending order. */
    let mut responses: [Option<Response>; u8::MAX as usize] = std::iter::repeat(None)
        .take(u8::MAX as usize)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut last_printed = 0;
    let mut final_hop = 0;
    let mut all_printed = HashSet::new();

    'mainloop: while let Some(msg) = rx.recv().await {
        match msg {
            Message::Ok(hop, hostname, ip_addr, time) => {
                responses[hop as usize - 1] =
                    Some(Response::TimeExceeded(hop, hostname.clone(), ip_addr, time));
            }
            Message::DestinationUnreachable(hop, hostname, ip_addr, time, code) => {
                responses[hop as usize - 1] = Some(Response::DestinationUnreachable(
                    hop,
                    hostname.clone(),
                    ip_addr,
                    time,
                    code,
                ));
            }
            Message::EchoReply(hop, hostname, ip_addr, time) => {
                responses[hop as usize - 1] =
                    Some(Response::EchoReply(hop, hostname.clone(), ip_addr, time));
                final_hop = hop;
            }
            Message::Timeout(hop) => {
                responses[hop as usize - 1] = Some(Response::Timeout(hop));
            }
        }

        while last_printed < u8::MAX && responses[last_printed as usize].is_some() {
            if let Some(response) = responses[last_printed as usize].clone() {
                match response.clone() {
                    Response::TimeExceeded(hop, hostname, ip_addr, time) => {
                        if !all_printed.contains(&ip_addr) {
                            println!("{}: {} ({}) - {:?}", hop, hostname, ip_addr, time);
                            all_printed.insert(ip_addr);
                        }
                        last_printed += 1;
                    }
                    Response::Timeout(hop) => {
                        println!("{}:  *** ", hop);
                        last_printed += 1;
                    }
                    Response::DestinationUnreachable(hop, hostname, ip_addr, time, code) => {
                        if !all_printed.contains(&ip_addr) {
                            println!(
                                "{}: {} ({}) - {:?} -- destination unreachable ({:?})",
                                hop, hostname, ip_addr, time, code
                            );
                            all_printed.insert(ip_addr);
                        }
                        last_printed += 1;
                        final_hop = hop;
                    }
                    Response::EchoReply(hop, hostname, ip_addr, time) => {
                        if !all_printed.contains(&ip_addr) {
                            println!(
                                "{}: {} ({}) - {:?} -- echo reply",
                                hop, hostname, ip_addr, time
                            );
                            all_printed.insert(ip_addr);
                        }
                        last_printed += 1;
                        final_hop = hop;
                    }
                }
            }

            if last_printed == final_hop {
                break 'mainloop;
            }
        }
    }
    semaphore.close();
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
    packet.set_identifier(0x1234);
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

fn to_ipaddr(target: &str) -> Result<Ipv4Addr> {
    match target.parse::<Ipv4Addr>() {
        Ok(addr) => Ok(addr),
        Err(_) => match dns_lookup::lookup_host(target) {
            Ok(ip_addrs) => match ip_addrs[0] {
                IpAddr::V4(addr) => Ok(addr),
                IpAddr::V6(_) => bail!("not implemented for ipv6."),
            },
            Err(_) => bail!("couldn't resolve the hostname"),
        },
    }
}

fn create_sock() -> Result<Arc<RawSocket>> {
    match RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()) {
        Ok(sock) => Ok(Arc::new(sock)),
        Err(_) => bail!("couldn't create the socket"),
    }
}

async fn time_for_hop(timetable: &Arc<Mutex<HashMap<u8, Instant>>>, hop: u8) -> Result<Duration> {
    match timetable.lock().await.get(&hop) {
        Some(time) => Ok(Instant::now().duration_since(*time)),
        None => bail!("did not find time {} in the timetable", hop),
    }
}

#[derive(Copy, Clone)]
enum TracerouteProtocol {
    Icmp,
    Udp,
}

impl FromStr for TracerouteProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "icmp" => Ok(TracerouteProtocol::Icmp),
            "udp" => Ok(TracerouteProtocol::Udp),
            _ => bail!("unsupported protocol: {}", s),
        }
    }
}

enum NextPacket<'a> {
    Udp(MutableUdpPacket<'a>),
    Icmp(MutableEchoRequestPacket<'a>),
}

#[derive(Debug, Clone)]
enum Response {
    TimeExceeded(u8, String, SocketAddr, Duration),
    DestinationUnreachable(u8, String, SocketAddr, Duration, IcmpCode),
    EchoReply(u8, String, SocketAddr, Duration),
    Timeout(u8),
}

#[derive(Debug)]
enum Message {
    Ok(u8, String, SocketAddr, Duration),
    DestinationUnreachable(u8, String, SocketAddr, Duration, IcmpCode),
    EchoReply(u8, String, SocketAddr, Duration),
    Timeout(u8),
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short = "p", long = "protocol", default_value="icmp"]]
    protocol: String,
}
