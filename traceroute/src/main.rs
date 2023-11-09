use anyhow::{bail, Result};
use libc::{getnameinfo, sockaddr, sockaddr_in, socklen_t, NI_MAXHOST};
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
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Semaphore,
    },
    time::{Duration, Instant},
};
use tracing::{error, info};

const START_TTL: u8 = 0;
const MAX_TASKS_IN_FLIGHT: usize = 4;

const IP_HDR_LEN: usize = 20;
const ICMP_HDR_LEN: usize = 8;
const UDP_HDR_LEN: usize = 8;

const TRACEROUTE_PORT: usize = 33434;

const IPPROTO_RAW: i32 = 255;
const NI_IDN: i32 = 0;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();
    let result = run(&opt.target, &opt.protocol).await;

    if let Err(e) = result {
        eprintln!("traceroute: {}", e);
    }
}

async fn run(target: &str, protocol: &str) -> Result<()> {
    let target_ip = to_ipaddr(target)?;
    let protocol = protocol.parse::<TracerouteProtocol>()?;

    info!("traceroute for {} using {:?}", target_ip, protocol);

    let semaphore = Arc::new(Semaphore::new(MAX_TASKS_IN_FLIGHT));

    /* Protected access to these variables that are shared across the tasks is needed
     * to synchronize them and prevent race conditions, by e.g. having two tasks updating
     * the TTL simultaneously. */
    let ttl = Arc::new(Mutex::new(START_TTL));
    let timetable = Arc::new(Mutex::new(HashMap::new()));
    let id_table = Arc::new(Mutex::new(HashMap::new()));

    /* Memory channels for communicating between the printer and the receiver. */
    let (tx1, rx1) = channel(1024);
    let (tx2, rx2) = channel(2);

    let responses: [Vec<Message>; u8::MAX as usize] = std::iter::repeat(Vec::new())
        .take(u8::MAX as usize)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let responses = Arc::new(Mutex::new(responses));

    let printer = tokio::spawn(print_results(responses.clone(), id_table.clone(), rx1, tx2));
    info!("printer: spawned");

    let receiver = tokio::spawn(receive(
        semaphore.clone(),
        timetable.clone(),
        id_table.clone(),
        tx1.clone(),
        rx2,
    ));
    info!("receiver: spawned");

    let mut tasks = vec![];

    for n in 0..u8::MAX {
        tasks.push(tokio::spawn(trace(
            n,
            tx1.clone(),
            responses.clone(),
            id_table.clone(),
            target_ip,
            protocol,
            semaphore.clone(),
            ttl.clone(),
            timetable.clone(),
        )));
        info!("tracer {}: spawned", n);
    }

    for (n, task) in tasks.into_iter().enumerate() {
        info!("awaiting task {}", n);
        task.await??;
    }
    info!("awaited all tasks");

    receiver.await??;
    info!("awaited receiver");

    printer.await??;
    info!("awaited printer");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn trace(
    n: u8,
    tx1: Sender<Message>,
    responses: Arc<Mutex<[Vec<Message>; u8::MAX as usize]>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    semaphore: Arc<Semaphore>,
    ttl: Arc<Mutex<u8>>,
    timetable: Arc<Mutex<HashMap<u16, Instant>>>,
) -> Result<()> {
    /* Allow no more than MAX_TASKS_IN_FLIGHT tasks to run concurrently.
     * We are limiting the number of tasks in flight so we don't end up
     * sending more packets than needed by spawning too many tasks. */
    info!("tracer {} wants to acquire the semaphore", n);
    if let Ok(permit) = semaphore.acquire().await {
        /* Each task increments the TTL and sends a probe. */
        info!("tracer {} successfully acquired the semaphore", n);

        let ttl = {
            let mut counter = ttl.lock().unwrap();
            *counter += 1;
            *counter
        };

        for numprobe in 0..3 {
            info!(
                "tracer {} probing ttl {} for the {}. time",
                n,
                ttl,
                numprobe + 1
            );
            // println!("send_probe: ttl {} numprobe {}", ttl, numprobe + 1);
            send_probe(
                target,
                protocol,
                ttl,
                numprobe + 1,
                timetable.clone(),
                id_table.clone(),
            )
            .await?;

            /* Marking the response as not received. */
            tokio::time::sleep(Duration::from_secs(1)).await;

            {
                info!(
                    "tracer {} thinks ttl {} numprobe {} timed out",
                    n,
                    ttl,
                    numprobe + 1
                );

                let response = {
                    let guard = { responses.lock().unwrap() };
                    guard[ttl as usize - 1].get(numprobe).cloned()
                };

                if response.is_none() {
                    info!("tracer {}: ttl {} definitely timed out", n, ttl);
                    if tx1
                        .send(Message::Timeout(Payload {
                            id: ttl as u16,
                            numprobe: numprobe + 1,
                            hostname: None,
                            ip_addr: None,
                            rtt: None,
                        }))
                        .await
                        .is_err()
                    {
                        semaphore.close();
                        return Ok(());
                    }
                }
            }
        }

        info!("tracer {}: forgetting the permit", n);
        drop(permit);
    }

    info!("tracer {}: exiting", n);
    Ok(())
}

async fn send_probe(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    ttl: u8,
    numprobe: usize,
    timetable: Arc<Mutex<HashMap<u16, Instant>>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
) -> Result<()> {
    let sock = RawSocket::new(
        Domain::ipv4(),
        Type::raw(),
        Protocol::from(IPPROTO_RAW).into(),
    )?;

    let mut ipv4_buf = protocol.get_ipv4_buffer();
    let ip_next_hdr_len = protocol.get_next_header_length();
    let mut ip_next_hdr_buf = protocol.get_ipv4_next_header_buffer();
    let ip_next_hdr_protocol = protocol.get_next_header_protocol();
    let id = rand::random::<u16>();

    {
        let mut guard = id_table.lock().unwrap();
        guard.insert(id, (ttl, numprobe));
    }

    let mut ipv4_packet = build_ipv4_packet(
        &mut ipv4_buf,
        target,
        (IP_HDR_LEN + ip_next_hdr_len) as u16,
        ttl,
        id,
        ip_next_hdr_protocol,
    );

    let next_packet = protocol.build_next_packet(&mut ip_next_hdr_buf, id);
    ipv4_packet.set_payload(next_packet.packet());

    sock.set_sockopt(Level::IPV4, Name::IPV4_HDRINCL, &1i32)?;
    sock.set_sockopt(Level::IPV4, Name::IP_TTL, &i32::from(ttl))?;
    sock.send_to(ipv4_packet.packet(), (target, 33434)).await?;

    timetable.lock().unwrap().insert(id as u16, Instant::now());

    Ok(())
}

async fn receive(
    semaphore: Arc<Semaphore>,
    timetable: Arc<Mutex<HashMap<u16, Instant>>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
    tx1: Sender<Message>,
    mut rx2: Receiver<Message>,
) -> Result<()> {
    info!("receiver: inside");
    let recv_sock = create_sock()?;
    let mut recv_buf = [0u8; 576];
    let mut recvd = HashSet::new();
    let mut dns_cache = HashMap::new();

    loop {
        if let Ok(Message::BreakReceiver) = rx2.try_recv() {
            info!("receiver: got BreakReceiver, closing the semaphore and breaking");
            break;
        }

        let (_bytes_received, ip_addr) = recv_sock.recv_from(&mut recv_buf).await?;

        let icmp_packet = match IcmpPacket::new(&recv_buf[IP_HDR_LEN..]) {
            Some(packet) => packet,
            None => bail!("couldn't make icmp packet"),
        };

        let id = if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
            id_from_payload(icmp_packet.payload())
        } else {
            /* A part of the original IPv4 packet (header + at least first 8 bytes)
             * is contained in an ICMP error message. We use the identification fi-
             * eld to map responses back to correct hops. */
            let original_ipv4_packet = match Ipv4Packet::new(&recv_buf[IP_HDR_LEN + ICMP_HDR_LEN..])
            {
                Some(packet) => packet,
                None => bail!("couldn't make ivp4 packet"),
            };

            original_ipv4_packet.get_identification()
        };

        let rtt = time_for_id(&timetable, id).await?;

        if !recvd.contains(&id) {
            recvd.insert(id);
        } else {
            println!("receiving duplicates");
            continue;
        }

        let hostname = dns_cache
            .entry(ip_addr)
            .or_insert(match reverse_dns_lookup(ip_addr).await {
                Ok(host) => host,
                Err(e) => {
                    eprintln!("{}", e);
                    panic!("spam");
                }
            })
            .clone();

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                let numprobe = numprobe_from_id(id_table.clone(), id)?;

                if tx1
                    .send(Message::TimeExceeded(Payload {
                        id,
                        numprobe,
                        hostname: Some(hostname),
                        ip_addr: Some(ip_addr),
                        rtt: Some(rtt),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }

                semaphore.add_permits(1);
                info!("receiver: added one more permit");
            }
            IcmpTypes::EchoReply => {
                let numprobe = numprobe_from_id(id_table.clone(), id)?;

                info!("receiver: sending EchoReply for hop {}", id);
                if tx1
                    .send(Message::EchoReply(Payload {
                        id,
                        numprobe,
                        hostname: Some(hostname),
                        ip_addr: Some(ip_addr),
                        rtt: Some(rtt),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            IcmpTypes::DestinationUnreachable => {
                let numprobe = numprobe_from_id(id_table.clone(), id)?;

                info!("receiver: sending DestinationUnreachable for hop {}", id);
                if tx1
                    .send(Message::DestinationUnreachable(Payload {
                        id,
                        numprobe,
                        hostname: Some(hostname),
                        ip_addr: Some(ip_addr),
                        rtt: Some(rtt),
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ => {}
        }
    }
    info!("receiver: exiting");

    Ok(())
}

async fn reverse_dns_lookup(ip_addr: SocketAddr) -> Result<String> {
    let ip = match ip_addr {
        SocketAddr::V4(ipv4_addr) => *ipv4_addr.ip(),
        SocketAddr::V6(_) => bail!("not implemented for ipv6"),
    };
    let sockaddr = SocketAddrV4::new(ip, 0);
    let sockaddr_in = sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(sockaddr.ip().octets()),
        },
        sin_zero: [0; 8],
    };

    tokio::task::spawn_blocking(move || {
        let mut host = [0 as libc::c_char; NI_MAXHOST as usize];

        let ret = unsafe {
            getnameinfo(
                &sockaddr_in as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
                host.as_mut_ptr(),
                host.len() as socklen_t,
                std::ptr::null_mut(),
                0,
                NI_IDN,
            )
        };

        if ret != 0 {
            error!("getnameinfo for {} failed: {}", ip, ret);
            bail!("getnameinfo for {} failed: {}", ip, ret);
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        Ok(c_str.to_str()?.to_string())
    })
    .await
    .unwrap()
}
fn hop_from_id(id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>, id: u16) -> Result<u8> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.0)
    } else {
        bail!("id {} not found", id);
    }
}

fn numprobe_from_id(id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>, id: u16) -> Result<usize> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.1)
    } else {
        bail!("id {} not found", id);
    }
}

fn sort(v: &mut [Message]) {
    v.sort_by(|a, b| {
        let numprobe_a = match a {
            Message::TimeExceeded(payload)
            | Message::DestinationUnreachable(payload)
            | Message::EchoReply(payload) => payload.numprobe,
            Message::Timeout(payload) => payload.numprobe,
            _ => 0, // Handle non-Payload messages as needed
        };
        let numprobe_b = match b {
            Message::TimeExceeded(payload)
            | Message::DestinationUnreachable(payload)
            | Message::EchoReply(payload) => payload.numprobe,
            Message::Timeout(payload) => payload.numprobe,
            _ => 0, // Handle non-Payload messages as needed
        };
        numprobe_b.cmp(&numprobe_a)
    });
}

macro_rules! print_probe {
    ($payload:expr, $hop:expr, $expected_numprobe:expr, $last_printed:expr, $mainloop:lifetime) => {{
        if $hop == $last_printed + 1 && $payload.numprobe == *$expected_numprobe {
            if $payload.numprobe == 1 {
                if $payload.hostname.is_some() {
                    print!(
                        "{}: {} ({}) - {:?} ",
                        $hop, $payload.hostname.unwrap(), $payload.ip_addr.unwrap(), $payload.rtt.unwrap()
                    );
                } else {
                    print!("{}: ", $hop);
                    print!("* ");
                }
                std::io::stdout().flush()?;
                *$expected_numprobe += 1;

                continue $mainloop;
            } else if $payload.numprobe > 1 && $payload.numprobe < 3 {
                if $payload.rtt.is_some() {
                    print!("- {:?} ", $payload.rtt.unwrap());
                } else {
                    print!("* ");
                }
                std::io::stdout().flush()?;
                *$expected_numprobe += 1;

                continue $mainloop;
            } else if $payload.numprobe == 3 {
                if $payload.rtt.is_some() {
                    println!("- {:?}", $payload.rtt.unwrap());
                } else {
                    println!("*");
                }
                $last_printed += 1;
            }
        }
    }};
}

async fn print_results(
    responses: Arc<Mutex<[Vec<Message>; u8::MAX as usize]>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
    mut rx1: Receiver<Message>,
    tx2: Sender<Message>,
) -> Result<()> {
    info!("printer: inside");
    /* The printer awaits messages from the receiver. Sometimes, the messages
     * arrive out of order, so the printer's job is to sort that out and print
     * the hops in ascending order. */
    let mut last_printed = 0;
    let mut final_hop = 0;
    let mut expected_numprobes: HashMap<_, _> = (0..255).map(|key| (key, 1)).collect();

    'mainloop: while let Some(msg) = rx1.recv().await {
        let mut rguard = { responses.lock().unwrap() };
        match msg.clone() {
            Message::TimeExceeded(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id)?;
                rguard[hop as usize - 1].push(msg);
                sort(&mut rguard[hop as usize - 1]);
                info!("printer: got TimeExceeded for hop {}", hop);
            }
            Message::DestinationUnreachable(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                rguard[hop as usize - 1].push(msg);
                sort(&mut rguard[hop as usize - 1]);

                info!("printer: got DestinationUnreachable for hop {}", hop);

                if final_hop == 0 {
                    final_hop = hop;
                    info!("printer: set final_hop to {}", final_hop);
                }
            }
            Message::EchoReply(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();

                rguard[hop as usize - 1].push(msg);
                sort(&mut rguard[hop as usize - 1]);
                info!("printer: got EchoReply for hop {}", hop);

                if final_hop == 0 {
                    final_hop = hop;
                    info!("printer: set final_hop to {}", final_hop);
                }
            }
            Message::Timeout(payload) => {
                info!(
                    "printer: got Timeout for hop {} numprobe {}",
                    payload.id, payload.numprobe
                );
                rguard[payload.id as usize - 1].push(msg);
                sort(&mut rguard[payload.id as usize - 1]);
            }
            _ => {}
        }

        while last_printed < u8::MAX && !rguard[last_printed as usize].is_empty() {
            if let Some(response) = rguard[last_printed as usize].pop() {
                match response.clone() {
                    Message::TimeExceeded(payload) => {
                        let hop = hop_from_id(id_table.clone(), payload.id)?;
                        let expected_numprobe = expected_numprobes.get_mut(&hop).unwrap();

                        print_probe!(payload, hop, expected_numprobe, last_printed, 'mainloop);
                    }
                    Message::DestinationUnreachable(payload) => {
                        let hop = hop_from_id(id_table.clone(), payload.id)?;
                        let expected_numprobe = expected_numprobes.get_mut(&hop).unwrap();

                        print_probe!(payload, hop, expected_numprobe, last_printed, 'mainloop);
                    }
                    Message::EchoReply(payload) => {
                        let hop = hop_from_id(id_table.clone(), payload.id)?;
                        let expected_numprobe = expected_numprobes.get_mut(&hop).unwrap();

                        print_probe!(payload, hop, expected_numprobe, last_printed, 'mainloop);
                    }
                    Message::Timeout(payload) => {
                        let expected_numprobe =
                            expected_numprobes.get_mut(&(payload.id as u8)).unwrap();

                        print_probe!(payload, payload.id as u8, expected_numprobe, last_printed, 'mainloop);
                    }
                    _ => {}
                }
            }

            let expected_numprobe = expected_numprobes.get(&final_hop).unwrap();
            if last_printed != 0 && *expected_numprobe == 3 && last_printed == final_hop {
                info!("printer: printed final_hop ({})", final_hop);
                break 'mainloop;
            }
        }
    }
    if tx2.send(Message::BreakReceiver).await.is_ok() {
        info!("printer: sent BreakReceiver");
    }

    info!("printer: exiting");
    Ok(())
}

fn build_ipv4_packet(
    buf: &mut [u8],
    dest: Ipv4Addr,
    size: u16,
    ttl: u8,
    id: u16,
    next_header: IpNextHeaderProtocol,
) -> MutableIpv4Packet {
    use pnet::packet::ipv4::checksum;

    let mut packet = MutableIpv4Packet::new(buf).unwrap();

    packet.set_version(4);
    packet.set_ttl(ttl);
    packet.set_header_length(5); /* n * 32 bits. */

    /* We are setting the identification field to the TTL
     * that we later use to map responses back to correct hops. */
    packet.set_identification(id);
    packet.set_next_level_protocol(next_header);
    packet.set_destination(dest);
    packet.set_flags(Ipv4Flags::DontFragment);
    packet.set_total_length(size);
    packet.set_checksum(checksum(&packet.to_immutable()));

    packet
}

fn build_icmp_packet(buf: &mut [u8], id: u16) -> NextPacket {
    use pnet::packet::icmp::checksum;

    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();
    let seq_no = rand::random::<u16>();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_sequence_number(seq_no);
    packet.set_identifier(id);
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

fn id_from_payload(payload: &[u8]) -> u16 {
    let identifier = &payload[0..2];
    let mut id = identifier[0] as u16;
    id <<= 8;
    id |= identifier[1] as u16;
    id
}

fn create_sock() -> Result<Arc<RawSocket>> {
    match RawSocket::new(Domain::ipv4(), Type::raw(), Protocol::icmpv4().into()) {
        Ok(sock) => Ok(Arc::new(sock)),
        Err(_) => bail!("couldn't create the socket"),
    }
}

async fn time_for_id(timetable: &Arc<Mutex<HashMap<u16, Instant>>>, id: u16) -> Result<Duration> {
    match timetable.lock().unwrap().get(&id) {
        Some(time) => Ok(Instant::now().duration_since(*time)),
        None => bail!("did not find time {} in the timetable", id),
    }
}

#[derive(Debug, Copy, Clone)]
enum TracerouteProtocol {
    Icmp,
    Udp,
}

impl TracerouteProtocol {
    fn get_ipv4_buffer(&self) -> Vec<u8> {
        match self {
            TracerouteProtocol::Udp => vec![0u8; IP_HDR_LEN + UDP_HDR_LEN],
            TracerouteProtocol::Icmp => vec![0u8; IP_HDR_LEN + ICMP_HDR_LEN],
        }
    }

    fn get_ipv4_next_header_buffer(&self) -> Vec<u8> {
        match self {
            TracerouteProtocol::Udp => vec![0u8; UDP_HDR_LEN],
            TracerouteProtocol::Icmp => vec![0u8; ICMP_HDR_LEN],
        }
    }

    fn get_next_header_length(&self) -> usize {
        match self {
            TracerouteProtocol::Udp => UDP_HDR_LEN,
            TracerouteProtocol::Icmp => ICMP_HDR_LEN,
        }
    }

    fn get_next_header_protocol(&self) -> IpNextHeaderProtocol {
        match self {
            TracerouteProtocol::Udp => IpNextHeaderProtocols::Udp,
            TracerouteProtocol::Icmp => IpNextHeaderProtocols::Icmp,
        }
    }

    fn build_next_packet<'a>(&'a self, next_hdr_buf: &'a mut [u8], id: u16) -> NextPacket {
        match self {
            TracerouteProtocol::Udp => build_udp_packet(next_hdr_buf),
            TracerouteProtocol::Icmp => build_icmp_packet(next_hdr_buf, id),
        }
    }
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

impl<'a> NextPacket<'a> {
    fn packet(&self) -> &[u8] {
        match self {
            NextPacket::Udp(packet) => packet.packet(),
            NextPacket::Icmp(packet) => packet.packet(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Payload {
    id: u16,
    numprobe: usize,
    hostname: Option<String>,
    ip_addr: Option<SocketAddr>,
    rtt: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq)]
enum Message {
    TimeExceeded(Payload),
    DestinationUnreachable(Payload),
    EchoReply(Payload),
    Timeout(Payload),
    BreakReceiver,
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short = "p", long = "protocol", default_value="icmp"]]
    protocol: String,
}
