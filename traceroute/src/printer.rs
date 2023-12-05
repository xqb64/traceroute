use crate::{
    internal::{hop_from_id, Message, Payload},
    IdTable,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info, instrument};

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
                add_msg!(id_table, hop, rguard, msg);

                debug!("got TimeExceeded for hop {hop}");
            }
            Message::DestinationUnreachable(payload) | Message::EchoReply(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg.clone());

                let icmp_type = if let Message::DestinationUnreachable(_) = msg {
                    "DestinationUnreachable"
                } else {
                    "EchoReply"
                };

                debug!("got {icmp_type} for hop {hop}");

                if final_hop == 0 || hop < final_hop {
                    final_hop = hop;
                }
                info!("set final_hop to {final_hop}");
            }
            Message::Timeout(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg);

                let numprobe = payload.numprobe;
                debug!("got Timeout for hop {hop} (numprobe {numprobe})");
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

                        let should_continue =
                            print_probe(&payload, hop, expected_numprobe, &mut last_printed);

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
                info!("printed final_hop ({final_hop}), breaking");
                break 'mainloop;
            }
        }
    }

    if tx2.send(Message::Quit).await.is_ok() {
        info!("sent Quit");
    }

    info!("exiting");

    Ok(())
}

fn print_probe(
    payload: &Payload,
    hop: u8,
    expected_numprobe: &mut u8,
    last_printed: &mut u8,
) -> Result<bool> {
    if hop == *last_printed + 1 && payload.numprobe == *expected_numprobe {
        if payload.numprobe == 1 {
            if payload.hostname.is_some() {
                print!(
                    "{}: {} ({}) - {:?} ",
                    hop,
                    payload.hostname.clone().unwrap(),
                    payload.ip_addr.unwrap(),
                    payload.rtt.unwrap()
                );
            } else {
                print!("{}: ", hop);
                print!("* ");
            }

            std::io::stdout().flush()?;

            *expected_numprobe += 1;

            return Ok(true);
        } else if payload.numprobe > 1 && payload.numprobe < 3 {
            if payload.rtt.is_some() {
                print!("- {:?} ", payload.rtt.unwrap());
            } else {
                print!("* ");
            }
            std::io::stdout().flush()?;
            *expected_numprobe += 1;

            return Ok(true);
        } else if payload.numprobe == 3 {
            if payload.rtt.is_some() {
                println!("- {:?}", payload.rtt.unwrap());
            } else {
                println!("*");
            }
            *last_printed += 1;

            return Ok(false);
        }
    }
    Ok(true)
}
