use anyhow::Result;

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use tokio::{select, sync::mpsc::channel, time::Duration};
use traceroute::receiver::recv;
use traceroute::tracer::send_probe;
use traceroute::{internal::numprobe_from_id, printer::print_results};
use traceroute::{internal::Message, net::create_sock};
use traceroute::{
    internal::Payload,
    net::{to_ipaddr, TracerouteProtocol},
};
use tracing::debug;

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
    let target_ip = to_ipaddr(target).await?;
    let protocol = protocol.parse::<TracerouteProtocol>()?;

    debug!("traceroute for {target_ip} using {protocol:?}");

    let id_table = Arc::new(Mutex::new(HashMap::new()));
    let time_table = Arc::new(Mutex::new(HashMap::new()));

    let mut v = VecDeque::new();

    let (tx1, rx1) = channel(1024);
    let (tx2, mut rx2) = channel(1);

    let responses: [Vec<Message>; u8::MAX as usize] = std::iter::repeat(Vec::new())
        .take(u8::MAX as usize)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let responses = Arc::new(Mutex::new(responses));

    let printer = tokio::spawn(print_results(responses, id_table.clone(), rx1, tx2));

    let mut recv_sock = create_sock()?;
    let recv_buf = [0u8; 576];
    let mut dns_cache = HashMap::new();

    let mut ttl = 1;

    for _ in 0..8 {
        for numprobe in 1..=3 {
            let id_table = id_table.clone();
            let time_table = time_table.clone();
            let (id, time_sent) = send_probe(
                target_ip,
                protocol,
                ttl,
                numprobe,
                id_table.clone(),
                time_table,
            )
            .await?;

            v.push_back((ttl, time_sent + Duration::from_secs(3), id));
        }

        ttl += 1;
    }

    loop {
        let id_table = id_table.clone();

        if let Ok(Message::Quit) = rx2.try_recv() {
            break;
        }

        select! {
            Ok(ident) = recv(&mut recv_sock, recv_buf, id_table.clone(), time_table.clone(), &mut dns_cache, tx1.clone()) => {
                v.remove(v.iter().position(|(_, _, id)| *id == ident).unwrap());
            }
            _ = tokio::time::sleep_until(v[0].1) => {
                let id = v[0].2;
                let numprobe = numprobe_from_id(id_table.clone(), id)?;
                tx1.send(Message::Timeout(Payload { id, numprobe, hostname: None, ip_addr: None, rtt: None })).await?;
                v.pop_front();
            },
        };

        for numprobe in 1..=3 {
            let id_table = id_table.clone();
            let time_table = time_table.clone();
            let (id, time_sent) = send_probe(
                target_ip,
                protocol,
                ttl,
                numprobe,
                id_table.clone(),
                time_table,
            )
            .await?;

            v.push_back((ttl, time_sent + Duration::from_secs(3), id));
        }

        ttl += 1;
    }

    printer.await??;

    Ok(())
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short = "p", long = "protocol", default_value="icmp"]]
    protocol: String,
}
