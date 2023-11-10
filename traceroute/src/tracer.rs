use crate::internal::{Message, Payload};
use crate::net::{build_ipv4_packet, TracerouteProtocol, IPPROTO_RAW, IP_HDR_LEN};
use anyhow::Result;
use pnet::packet::Packet;
use raw_socket::{
    tokio::prelude::{Level, Name, RawSocket},
    Domain, Protocol, Type,
};
use std::{
    collections::{hash_map::Entry::Vacant, HashMap},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{mpsc::Sender, Semaphore},
    time::{Duration, Instant},
};
use tracing::{debug, error, info, instrument, warn};

#[allow(clippy::too_many_arguments)]
#[instrument(
    skip(tx1, responses, id_table, target, protocol, semaphore, ttl, timetable),
    name = "tracer"
)]
pub async fn trace(
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
    debug!("trying to acquire the semaphore");
    if let Ok(permit) = semaphore.acquire().await {
        /* Each task increments the TTL and sends a probe. */
        debug!("successfully acquired the semaphore");

        let ttl = {
            let mut counter = ttl.lock().unwrap();
            *counter += 1;
            *counter
        };

        for numprobe in 1..=3 {
            if semaphore.is_closed() {
                warn!("break because of the closed semaphore");
                break;
            }

            info!("probing ttl {ttl} for the {numprobe}. time",);
            // println!("send_probe: ttl {} numprobe {}", ttl, numprobe + 1);
            let id = send_probe(
                target,
                protocol,
                ttl,
                numprobe,
                timetable.clone(),
                id_table.clone(),
            )
            .await?;

            /* Marking the response as not received. */
            tokio::time::sleep(Duration::from_secs(1)).await;

            {
                debug!("thinking ttl {ttl} numprobe {numprobe} timed out");

                let response = {
                    let guard = { responses.lock().unwrap() };
                    guard[ttl as usize - 1].get(numprobe - 1).cloned()
                };

                if response.is_none() {
                    debug!("ttl {ttl} definitely timed out");
                    if tx1
                        .send(Message::Timeout(Payload {
                            id,
                            numprobe,
                            hostname: None,
                            ip_addr: None,
                            rtt: None,
                        }))
                        .await
                        .is_err()
                    {
                        error!("sending Timeout to printer failed");
                        return Ok(());
                    }
                }
            }
        }

        debug!("forgetting the permit");
        drop(permit);
    }

    info!("exiting");
    Ok(())
}

#[instrument(skip(target, protocol, timetable, id_table), name = "prober")]
async fn send_probe(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    ttl: u8,
    numprobe: usize,
    timetable: Arc<Mutex<HashMap<u16, Instant>>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
) -> Result<u16> {
    let sock = RawSocket::new(
        Domain::ipv4(),
        Type::raw(),
        Protocol::from(IPPROTO_RAW).into(),
    )?;

    let mut ipv4_buf = protocol.get_ipv4_buffer();
    let ip_next_hdr_len = protocol.get_next_header_length();
    let mut ip_next_hdr_buf = protocol.get_ipv4_next_header_buffer();
    let ip_next_hdr_protocol = protocol.get_next_header_protocol();
    let mut id;

    {
        let mut guard = id_table.lock().unwrap();
        loop {
            id = rand::random::<u16>();
            if let Vacant(e) = guard.entry(id) {
                e.insert((ttl, numprobe));
                break;
            } else {
                warn!("generated random id {id}, trying again");
            }
        }
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

    timetable.lock().unwrap().insert(id, Instant::now());

    Ok(id)
}
