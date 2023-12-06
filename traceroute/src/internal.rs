use crate::{error_and_bail, IdTable, TimeTable};
use anyhow::{bail, Result};
use std::net::SocketAddr;
use tokio::time::{Duration, Instant};
use tracing::error;

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    TimeExceeded(Payload),
    DestinationUnreachable(Payload),
    EchoReply(Payload),
    Timeout(Payload),
    Quit,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::TimeExceeded(_) => write!(f, "TimeExceeded"),
            Message::DestinationUnreachable(_) => write!(f, "DestinationUnreachable"),
            Message::EchoReply(_) => write!(f, "EchoReply"),
            Message::Timeout(_) => write!(f, "Timeout"),
            Message::Quit => write!(f, "Quit"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub id: u16,
    pub numprobe: u8,
    pub hostname: Option<String>,
    pub ip_addr: Option<SocketAddr>,
    pub rtt: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub ttl: u8,
    pub timeout: Instant,
    pub id: u16,
}

pub fn hop_from_id(id_table: IdTable, id: u16) -> Result<u8> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.0)
    } else {
        error_and_bail!("id {id} not found in id_table");
    }
}

pub fn numprobe_from_id(id_table: IdTable, id: u16) -> Result<u8> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.1)
    } else {
        error_and_bail!("id {id} not found in id_table");
    }
}

pub fn time_from_id(timetable: TimeTable, instant: Instant, id: u16) -> Result<Duration> {
    match timetable.lock().unwrap().get(&id) {
        Some(time) => Ok(instant.duration_since(*time)),
        None => error_and_bail!("id {id} not found in timetable"),
    }
}
