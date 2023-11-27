use crate::error_and_bail;
use crate::internal::{hop_from_id, numprobe_from_id, time_from_id, Message, Payload};
use crate::net::{create_sock, id_from_payload, reverse_dns_lookup, ICMP_HDR_LEN, IP_HDR_LEN};
use anyhow::{bail, Result};
use pnet::packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ipv4::Ipv4Packet,
    Packet,
};
use std::collections::hash_map::Entry;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};
use tracing::{debug, error, info, instrument, warn};

#[instrument(skip_all, name = "receiver")]
pub async fn receive(
    timetable: Arc<Mutex<HashMap<u16, Instant>>>,
    id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>,
    tx1: Sender<Message>,
    mut rx2: Receiver<Message>,
) -> Result<()> {
    debug!("receiver: inside");
    let recv_sock = create_sock()?;
    let mut recv_buf = [0u8; 576];
    let mut recvd = HashSet::new();
    let mut dns_cache = HashMap::new();
    let mut final_hop = 0;

    loop {
        if let Ok(Message::BreakReceiver) = rx2.try_recv() {
            info!("got BreakReceiver, breaking");
            break;
        }

        let (_bytes_received, ip_addr) = match tokio::time::timeout(
            tokio::time::Duration::from_millis(300),
            recv_sock.recv_from(&mut recv_buf),
        )
        .await
        {
            Ok(result) => result.unwrap(),
            Err(_) => continue,
        };

        let time_recvd = Instant::now();

        let icmp_packet = match IcmpPacket::new(&recv_buf[IP_HDR_LEN..]) {
            Some(packet) => packet,
            None => error_and_bail!("couldn't make icmp packet"),
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
                None => error_and_bail!("couldn't make ivp4 packet"),
            };

            original_ipv4_packet.get_identification()
        };

        if !recvd.contains(&id) {
            recvd.insert(id);
        } else {
            warn!("receiving duplicates for {id}");
            continue;
        }

        let rtt = time_from_id(timetable.clone(), time_recvd, id)?;

        if let Entry::Vacant(e) = dns_cache.entry(ip_addr) {
            match reverse_dns_lookup(ip_addr).await {
                Ok(host) => {
                    debug!(host, "resolving");
                    e.insert(host); // Insert the new host into the cache
                }
                Err(err) => {
                    error!("error on reverse_dns_lookup ({err})");
                    debug!("breaking printer and exiting");
                    tx1.send(Message::BreakPrinter).await?;
                    break;
                }
            }
        }

        let hostname = dns_cache.get(&ip_addr).unwrap().clone();

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                let numprobe = numprobe_from_id(id_table.clone(), id)?;
                let hop = hop_from_id(id_table.clone(), id)?;

                debug!("sending TimeExceeded for hop {hop}");
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
            }
            IcmpTypes::EchoReply => {
                let numprobe = numprobe_from_id(id_table.clone(), id)?;
                let hop = hop_from_id(id_table.clone(), id)?;

                if final_hop == 0 || hop < final_hop {
                    error!("received EchoReply for {hop}");
                    final_hop = hop;
                }

                if hop > final_hop {
                    continue;
                }

                debug!("sending EchoReply for hop {hop}");
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
                let hop = hop_from_id(id_table.clone(), id)?;

                if final_hop == 0 || hop < final_hop {
                    final_hop = hop;
                }

                if hop > final_hop {
                    warn!(hop, final_hop, "received hop > final_hop");
                    continue;
                }

                debug!("sending DestinationUnreachable for hop {hop}");
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

    info!("exiting");

    Ok(())
}
