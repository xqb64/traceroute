use crate::{
    internal::{hop_from_id, numprobe_from_id, Message, Payload},
    IdTable,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info, instrument, warn};

macro_rules! add_msg {
    ($id_table:expr, $hop:expr, $rguard:expr, $msg:expr) => {{
        $rguard[$hop as usize - 1].push($msg);
    }};
}

#[instrument(skip_all, name = "printer")]
pub async fn print_results(
    responses: Arc<Mutex<[Vec<Message>; u8::MAX as usize]>>,
    id_table: IdTable,
    mut rx1: Receiver<Message>,
    tx2: Sender<Message>,
    probes: u8,
) -> Result<()> {
    debug!("printer: inside");
    /* The printer awaits messages from the receiver. Sometimes, the messages
     * arrive out of order, so the printer's job is to sort that out and print
     * the hops in ascending order. */
    let mut last_printed = 0;
    let mut final_hop = 0;
    let mut expected_numprobes: HashMap<_, u8> = (1..255).map(|key| (key, 1)).collect();

    'mainloop: while let Some(msg) = rx1.recv().await {
        let mut rguard = { responses.lock().unwrap() };
        match msg.clone() {
            Message::TimeExceeded(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");
            }
            Message::DestinationUnreachable(payload) | Message::EchoReply(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");

                if final_hop == 0 || hop < final_hop {
                    final_hop = hop;
                    info!(final_hop, "set final_hop");
                }
            }
            Message::Timeout(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");
            }
            _ => {}
        }

        while last_printed < u8::MAX && !rguard[last_printed as usize].is_empty() {
            if let Some(response) = rguard[last_printed as usize].iter().find(|msg| match msg {
                Message::TimeExceeded(payload)
                | Message::DestinationUnreachable(payload)
                | Message::EchoReply(payload)
                | Message::Timeout(payload) => {
                    payload.numprobe == *expected_numprobes.get(&(last_printed + 1)).unwrap()
                }
                _ => false,
            }) {
                match response.clone() {
                    Message::TimeExceeded(payload)
                    | Message::DestinationUnreachable(payload)
                    | Message::EchoReply(payload)
                    | Message::Timeout(payload) => {
                        let hop = hop_from_id(id_table.clone(), payload.id)?;
                        let expected_numprobe = expected_numprobes.get_mut(&hop).unwrap();

                        let should_continue = print_probe(
                            &payload,
                            hop,
                            expected_numprobe,
                            &mut last_printed,
                            probes,
                        );

                        if should_continue.is_ok_and(|r| r) {
                            continue 'mainloop;
                        }
                    }
                    _ => {}
                }
            } else {
                continue 'mainloop;
            }

            if last_printed != 0 && last_printed == final_hop {
                info!(final_hop, "printed final_hop, breaking");
                break 'mainloop;
            }
        }
    }

    info!("sending Quit");
    if tx2.send(Message::Quit).await.is_err() {
        warn!("failed ot send Quit")
    }

    info!("exiting");

    Ok(())
}

fn print_probe(
    payload: &Payload,
    hop: u8,
    expected_numprobe: &mut u8,
    last_printed: &mut u8,
    probes: u8,
) -> Result<bool> {
    if hop != *last_printed + 1 || payload.numprobe != *expected_numprobe {
        return Ok(true);
    }

    match payload.numprobe {
        1 => {
            match (&payload.hostname, payload.ip_addr, payload.rtt) {
                (Some(hostname), Some(ip_addr), Some(rtt)) => {
                    print!("{}: {} ({}) - {:?} ", hop, hostname, ip_addr, rtt);
                }
                _ => print!("{}: * ", hop),
            }

            std::io::stdout().flush()?;

            *expected_numprobe += 1;

            Ok(true)
        }
        probe if (1..probes).contains(&probe) => {
            match payload.rtt {
                Some(rtt) => print!("- {:?} ", rtt),
                None => print!("* "),
            }

            std::io::stdout().flush()?;
            *expected_numprobe += 1;

            Ok(true)
        }
        _ if payload.numprobe == probes => {
            match payload.rtt {
                Some(rtt) => println!("- {:?} ", rtt),
                None => println!("*"),
            }

            *last_printed += 1;

            Ok(false)
        }
        _ => Ok(true),
    }
}
