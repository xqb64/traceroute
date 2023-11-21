use crate::internal::{time_from_id, Message, Payload};
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
    time::Instant,
};
use tracing::{debug, error, info, instrument, warn};

#[allow(clippy::too_many_arguments)]
#[instrument(
    skip_all,
    name = "tracer"
    fields(n = n)
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
    if let Ok(_permit) = semaphore.acquire().await {
        /* Each task increments the TTL and sends a probe. */
        debug!("successfully acquired the semaphore");

        let ttl = {
            let mut counter = ttl.lock().unwrap();
            *counter += 1;
            *counter
        };

        let mut ids = HashMap::new();

        for numprobe in 1..=3 {
            if semaphore.is_closed() {
                debug!("break because of the closed semaphore");
                break;
            }

            debug!("probing ttl {ttl} for the {numprobe}. time",);
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

            ids.insert((ttl, numprobe), (id, false));
        }

        {
            debug!("checking if ttl {ttl} timed out");

            loop {
                let responses = {
                    let guard = { responses.lock().unwrap() };
                    guard[ttl as usize - 1].clone()
                };

                if responses.iter().len() >= 3 {
                    debug!("break because all arrived");
                    break;
                }

                if semaphore.is_closed() {
                    debug!("break because semaphore is closed");
                    break;
                }

                for ((_ttl, numprobe), (id, sent_timeout)) in ids.iter_mut() {
                    if *sent_timeout {
                        debug!("already sent timeout fot ttl {_ttl} numprobe {numprobe}");
                        continue;
                    }
                    let now = tokio::time::Instant::now();
                    let time_waiting = time_from_id(timetable.clone(), now, *id)?;
                    if time_waiting >= tokio::time::Duration::from_secs(3) {
                        if tx1
                            .send(Message::Timeout(Payload {
                                id: *id,
                                numprobe: *numprobe,
                                hostname: None,
                                ip_addr: None,
                                rtt: None,
                            }))
                            .await
                            .is_err()
                        {
                            error!("sending Timeout to printer failed");
                        }
                        *sent_timeout = true;
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }

    info!("exiting");
    Ok(())
}

#[instrument(skip_all, name = "prober", fields(n = ttl))]
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
