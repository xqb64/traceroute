use anyhow::Result;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use structopt::StructOpt;
use tokio::sync::{mpsc::channel, Semaphore};
use traceroute::internal::Message;
use traceroute::net::{to_ipaddr, TracerouteProtocol};
use traceroute::printer::print_results;
use traceroute::receiver::receive;
use traceroute::tracer::trace;
use tracing::info;
use tracing_subscriber::{self, prelude::*};

const START_TTL: u8 = 0;
const MAX_TASKS_IN_FLIGHT: usize = 4;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("error")
        .finish()
        .init();

    let opt = Opt::from_args();
    let result = run(&opt.target, &opt.protocol).await;

    if let Err(e) = result {
        eprintln!("traceroute: {}", e);
    }
}

async fn run(target: &str, protocol: &str) -> Result<()> {
    let target_ip = to_ipaddr(target).await?;
    let protocol = protocol.parse::<TracerouteProtocol>()?;

    info!("traceroute for {target_ip} using {protocol:?}");

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

    let printer = tokio::spawn(print_results(
        responses.clone(),
        id_table.clone(),
        rx1,
        tx2,
        semaphore.clone(),
    ));
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
        info!("tracer {n}: spawned");
    }

    for (n, task) in tasks.into_iter().enumerate() {
        info!("awaiting task {n}");
        task.await??;
    }
    info!("awaited all tasks");

    receiver.await??;
    info!("awaited receiver");

    printer.await??;
    info!("awaited printer");

    Ok(())
}

#[derive(Debug, StructOpt)]
struct Opt {
    target: String,

    #[structopt[short = "p", long = "protocol", default_value="icmp"]]
    protocol: String,
}
