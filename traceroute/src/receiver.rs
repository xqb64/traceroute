use crate::internal::{hop_from_id, numprobe_from_id, time_from_id, Message, Payload};
use crate::net::{id_from_payload, reverse_dns_lookup, ICMP_HDR_LEN, IP_HDR_LEN};
use crate::{error_and_bail, IdTable, TimeTable};
use anyhow::{bail, Result};
use pnet::packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ipv4::Ipv4Packet,
    Packet,
};
use raw_socket::tokio::RawSocket;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::{sync::mpsc::Sender, time::Instant};
use tracing::{debug, error, info, instrument, warn};

#[instrument(skip_all, name = "receiver")]
pub async fn recv(
    recv_sock: &mut RawSocket,
    mut recv_buf: [u8; 576],
    id_table: IdTable,
    time_table: TimeTable,
    dns_cache: &mut HashMap<SocketAddr, String>,
    tx1: Sender<Message>,
) -> Result<u16> {
    info!("inside");
    let mut final_hop = 0;

    let (_bytes_received, ip_addr) = recv_sock.recv_from(&mut recv_buf).await?;

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
        let original_ipv4_packet = match Ipv4Packet::new(&recv_buf[IP_HDR_LEN + ICMP_HDR_LEN..]) {
            Some(packet) => packet,
            None => error_and_bail!("couldn't make ivp4 packet"),
        };

        original_ipv4_packet.get_identification()
    };

    let rtt = time_from_id(time_table.clone(), time_recvd, id)?;

    if let Entry::Vacant(e) = dns_cache.entry(ip_addr) {
        match reverse_dns_lookup(ip_addr).await {
            Ok(host) => {
                debug!(host, "resolving");
                e.insert(host); // Insert the new host into the cache
            }
            Err(err) => {
                error!("errored out on reverse_dns_lookup: {err}");
            }
        }
    }

    let hostname = dns_cache.get(&ip_addr).unwrap().clone();

    match icmp_packet.get_icmp_type() {
        IcmpTypes::TimeExceeded => {
            let numprobe = numprobe_from_id(id_table.clone(), id)?;
            let hop = hop_from_id(id_table.clone(), id)?;

            info!(hop, "sending TimeExceeded");
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
                warn!(hop, id, "failed sending TimeExceeded");
                return Ok(id);
            }
        }
        IcmpTypes::EchoReply => {
            let numprobe = numprobe_from_id(id_table.clone(), id)?;
            let hop = hop_from_id(id_table.clone(), id)?;

            /* We only want to set final_hop if it hasn't already been
             * set, or if the current final_hop we have is greater than
             * the one we just got. The latter could happen if the res-
             * ponse for hop 'n' arrives before the true final hop (x < n). */
            if final_hop == 0 || hop < final_hop {
                debug!(hop, "received EchoReply, setting final_hop");
                final_hop = hop;
            }

            if hop > final_hop {
                warn!(hop, final_hop, "received hop > final_hop");
            }

            info!(hop, "sending EchoReply");
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
                warn!(hop, id, "failed sending EchoReply");
                return Ok(id);
            }
        }
        IcmpTypes::DestinationUnreachable => {
            let numprobe = numprobe_from_id(id_table.clone(), id)?;
            let hop = hop_from_id(id_table.clone(), id)?;

            /* We only want to set final_hop if it hasn't already been
             * set, or if the current final_hop we have is greater than
             * the one we just got. The latter could happen if the res-
             * ponse for hop 'n' arrives before the true final hop (x < n). */
            if final_hop == 0 || hop < final_hop {
                debug!(hop, "received DestinationUnreachable, setting final_hop");
                final_hop = hop;
            }

            if hop > final_hop {
                warn!(hop, final_hop, "received hop > final_hop");
            }

            info!(hop, "sending DestinationUnreachable");
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
                warn!(hop, id, "failed sending DestinationUnreachable");
                return Ok(id);
            }
        }
        _ => {}
    }

    info!("exiting");

    Ok(id)
}
