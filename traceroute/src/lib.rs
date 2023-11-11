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
