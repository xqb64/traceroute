use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::time::Instant;

pub mod internal;
pub mod net;
pub mod printer;
pub mod receiver;
pub mod tracer;

#[macro_export]
macro_rules! error_and_bail {
    ($msg:literal) => {{
        error!($msg);
        bail!($msg);
    }};
}

pub type IdTable = Arc<Mutex<HashMap<u16, (u8, u8)>>>;
pub type TimeTable = Arc<Mutex<HashMap<u16, Instant>>>;
