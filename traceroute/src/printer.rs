use crate::internal::{hop_from_id, Message, Payload};
use anyhow::Result;
use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info};

macro_rules! add_msg {
    ($id_table:expr, $hop:expr, $rguard:expr, $msg:expr) => {{
        $rguard[$hop as usize - 1].push($msg);
        sort(&mut $rguard[$hop as usize - 1]);
    }};
}

pub async fn print_results(
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
    let mut expected_numprobes: HashMap<_, usize> = (0..255).map(|key| (key, 1)).collect();

    'mainloop: while let Some(msg) = rx1.recv().await {
        let mut rguard = { responses.lock().unwrap() };
        match msg.clone() {
            Message::TimeExceeded(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg);

                info!(r#"printer: got "TimeExceeded" for hop {}"#, hop);
            }
            Message::DestinationUnreachable(payload) | Message::EchoReply(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg.clone());

                info!(
                    "printer: got {:?} for hop {}",
                    if let Message::DestinationUnreachable(_) = msg {
                        "DestinationUnreachable"
                    } else {
                        "EchoReply"
                    },
                    hop
                );

                if final_hop == 0 {
                    final_hop = hop;
                    info!("printer: set final_hop to {}", final_hop);
                }
            }
            Message::Timeout(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(id_table, hop, rguard, msg);

                info!(
                    r#"printer: got "Timeout" for hop {} numprobe {}"#,
                    hop, payload.numprobe
                );
            }
            Message::BreakPrinter => {
                error!("printer: received BreakPrinter, breaking");
                break 'mainloop;
            }
            _ => {}
        }

        while last_printed < u8::MAX && !rguard[last_printed as usize].is_empty() {
            if let Some(response) = rguard[last_printed as usize].pop() {
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

fn print_probe(
    payload: &Payload,
    hop: u8,
    expected_numprobe: &mut usize,
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
