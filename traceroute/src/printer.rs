use crate::{
    internal::{hop_from_id, numprobe_from_id, Message, Payload},
    IdTable,
};
use anyhow::Result;
use std::{collections::HashMap, io::Write};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info, instrument, warn};

macro_rules! add_msg {
    ($responses:expr, $hop:expr, $msg:expr) => {{
        $responses[$hop as usize - 1].push($msg);
    }};
}

/// The printer awaits messages from the receiver. Sometimes, the messages
/// arrive out of order. The printer's job is to sort that out and print the
/// hops in ascending order.
#[instrument(skip_all, name = "printer")]
pub async fn print_results(
    id_table: IdTable,
    mut rx1: Receiver<Message>,
    tx2: Sender<Message>,
    probes: u8,
) -> Result<()> {
    debug!("printer: inside");

    let mut responses: [Vec<Message>; u8::MAX as usize] = std::iter::repeat(Vec::new())
        .take(u8::MAX as usize)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let mut last_printed = 0;
    let mut final_hop = 0;
    let mut expected_numprobes: HashMap<_, u8> = (1..255).map(|key| (key, 1)).collect();

    'mainloop: while let Some(msg) = rx1.recv().await {
        match msg.clone() {
            Message::TimeExceeded(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(responses, hop, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");
            }
            Message::DestinationUnreachable(payload) | Message::EchoReply(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(responses, hop, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");

                /* We only want to set final_hop if it hasn't already been
                 * set, or if the current final_hop we have is greater than
                 * the one we just got. The latter could happen if the res-
                 * ponse for hop 'n' arrives before the true final hop (x < n). */
                if final_hop == 0 || hop < final_hop {
                    final_hop = hop;
                    info!(final_hop, "set final_hop");
                }
            }
            Message::Timeout(payload) => {
                let hop = hop_from_id(id_table.clone(), payload.id).unwrap();
                add_msg!(responses, hop, msg.clone());

                let numprobe = numprobe_from_id(id_table.clone(), payload.id)?;
                debug!(hop, numprobe, "got message: {msg}");
            }
            _ => {}
        }

        while last_printed < u8::MAX && !responses[last_printed as usize].is_empty() {
            /* If there is some message with the next expected numprobe,
             * print it out. */
            if let Some(response) = responses[last_printed as usize]
                .iter()
                .find(|msg| match msg {
                    Message::TimeExceeded(payload)
                    | Message::DestinationUnreachable(payload)
                    | Message::EchoReply(payload)
                    | Message::Timeout(payload) => {
                        payload.numprobe == *expected_numprobes.get(&(last_printed + 1)).unwrap()
                    }
                    _ => false,
                })
            {
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
                /* Message with the next expected numprobe not found,
                 * continue receiving messages. */
                continue 'mainloop;
            }

            /* If the last printed hop was final_hop at the same time,
             * break the printer mainloop, and jump to sending Message::Quit
             * to the main thread. */
            if last_printed != 0 && last_printed == final_hop {
                info!(final_hop, "printed final_hop, breaking");
                break 'mainloop;
            }
        }
    }

    info!("sending Quit");
    if tx2.send(Message::Quit).await.is_err() {
        warn!("failed to send Message::Quit")
    }

    info!("exiting");

    Ok(())
}

/// Prints the probe provided it is the expected hop and expected numprobe.
/// Returns true if the printer should continue its mainloop (and try to
/// receive more messages).
fn print_probe(
    payload: &Payload,
    hop: u8,
    expected_numprobe: &mut u8,
    last_printed: &mut u8,
    probes: u8,
) -> Result<bool> {
    /* Check to see if this is the probe we should be printing. */
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

            /* Last numprobe, return false and let the
             * printer receive more messages. */
            Ok(false)
        }
        _ => Ok(true),
    }
}
