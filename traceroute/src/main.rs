use anyhow::Result;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use tokio::{
    select,
    sync::mpsc::channel,
    time::{sleep, sleep_until, Duration},
};
use traceroute::{
    internal::{numprobe_from_id, Message, Payload, Probe},
    net::{create_sock, to_ipaddr, TracerouteProtocol},
    printer::print_results,
    receiver::recv,
    tracer::send_probe,
};
use tracing::debug;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();
    let result = run(&opt.target, opt.protocol, opt.hops, opt.probes, opt.timeout).await;

    if let Err(e) = result {
        eprintln!("traceroute: {}", e);
    }
}

async fn run(
    target: &str,
    protocol: TracerouteProtocol,
    hops: u8,
    probes: u8,
    timeout: u64,
) -> Result<()> {
    let target_ip = to_ipaddr(target).await?;

    debug!("traceroute for {target_ip} using {protocol:?}");

    let id_table = Arc::new(Mutex::new(HashMap::new()));
    let time_table = Arc::new(Mutex::new(HashMap::new()));

    let mut v = VecDeque::new();

    let (tx1, rx1) = channel(1024);
    let (tx2, mut rx2) = channel(1);

    let printer = tokio::spawn(print_results(id_table.clone(), rx1, tx2, probes));

    let mut recv_sock = create_sock()?;
    let recv_buf = [0u8; 576];
    let mut dns_cache = HashMap::new();

    'mainloop: for batch in (1..=hops).collect::<Vec<u8>>().chunks(4) {
        for ttl in batch {
            for numprobe in 1..=probes {
                let (id, time_sent) = send_probe(
                    target_ip,
                    protocol,
                    *ttl,
                    numprobe,
                    id_table.clone(),
                    time_table.clone(),
                )
                .await?;

                v.push_back(Probe {
                    ttl: *ttl,
                    timeout: time_sent + Duration::from_secs(timeout),
                    id,
                });

                sleep(Duration::from_millis(10)).await;
            }
        }
        loop {
            if v.is_empty() {
                break;
            }

            if let Ok(Message::Quit) = rx2.try_recv() {
                break 'mainloop;
            }

            select! {
                Ok(ident) = recv(
                    &mut recv_sock,
                    recv_buf,
                    id_table.clone(),
                    time_table.clone(),
                    &mut dns_cache,
                    tx1.clone(),
                ) => {
                    v.retain(|probe| probe.id != ident);
                }
                _ = sleep_until(v[0].timeout) => {
                    let id = v[0].id;
                    let numprobe = numprobe_from_id(id_table.clone(), id)?;
                    tx1.send(Message::Timeout(Payload {
                        id,
                        numprobe,
                        hostname: None,
                        ip_addr: None,
                        rtt: None,
                    }))
                    .await?;
                    v.pop_front();
                },
            };
        }
    }

    printer.await??;

    Ok(())
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short, long, default_value="udp"]]
    protocol: TracerouteProtocol,

    #[structopt[short, long, default_value="30"]]
    hops: u8,

    #[structopt[short = "P", long, default_value="3"]]
    probes: u8,

    #[structopt[short, long, default_value="3"]]
    timeout: u64,
}
