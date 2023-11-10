use anyhow::{bail, Result};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    TimeExceeded(Payload),
    DestinationUnreachable(Payload),
    EchoReply(Payload),
    Timeout(Payload),
    BreakReceiver,
    BreakPrinter,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub id: u16,
    pub numprobe: usize,
    pub hostname: Option<String>,
    pub ip_addr: Option<SocketAddr>,
    pub rtt: Option<Duration>,
}

pub fn hop_from_id(id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>, id: u16) -> Result<u8> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.0)
    } else {
        bail!("id {} not found", id);
    }
}

pub fn numprobe_from_id(id_table: Arc<Mutex<HashMap<u16, (u8, usize)>>>, id: u16) -> Result<usize> {
    if let Some(&entry) = id_table.lock().unwrap().get(&id) {
        Ok(entry.1)
    } else {
        bail!("id {} not found", id);
    }
}

pub async fn time_from_id(
    timetable: &Arc<Mutex<HashMap<u16, Instant>>>,
    id: u16,
) -> Result<Duration> {
    match timetable.lock().unwrap().get(&id) {
        Some(time) => Ok(Instant::now().duration_since(*time)),
        None => bail!("did not find time {} in the timetable", id),
    }
}
