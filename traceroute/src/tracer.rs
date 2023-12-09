use crate::{
    net::{build_ipv4_packet, TracerouteProtocol, IPPROTO_RAW, IP_HDR_LEN},
    IdTable, TimeTable,
};
use anyhow::Result;
use pnet::packet::Packet;
use raw_socket::{
    tokio::prelude::{Level, Name, RawSocket},
    Domain, Protocol, Type,
};
use std::{collections::hash_map::Entry::Vacant, net::Ipv4Addr};
use tokio::time::Instant;
use tracing::{info, instrument, warn};

#[instrument(skip_all, name = "prober", fields(n = ttl))]
pub async fn send_probe(
    target: Ipv4Addr,
    protocol: TracerouteProtocol,
    ttl: u8,
    numprobe: u8,
    id_table: IdTable,
    timetable: TimeTable,
) -> Result<(u16, Instant)> {
    let sock = RawSocket::new(
        Domain::ipv4(),
        Type::raw(),
        Protocol::from(IPPROTO_RAW).into(),
    )?;

    let mut ipv4_buf = protocol.get_ipv4_buffer();
    let ip_next_hdr_len = protocol.get_next_header_length();
    let mut ip_next_hdr_buf = protocol.get_ipv4_next_header_buffer();
    let ip_next_hdr_protocol = protocol.get_next_header_protocol();

    /* Generate random id while making sure it is not a duplicate. */
    let mut id;
    {
        let mut guard = id_table.lock().unwrap();
        loop {
            id = rand::random::<u16>();
            if let Vacant(e) = guard.entry(id) {
                e.insert((ttl, numprobe));
                break;
            } else {
                warn!(id, "generated duplicate random id, trying again");
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

    let time_sent = Instant::now();
    timetable.lock().unwrap().insert(id, time_sent);

    info!(ttl, "sent probe");

    Ok((id, time_sent))
}
