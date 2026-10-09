use std::fmt::Display;

use thiserror::Error;

// pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
}

pub trait TraceError<T, E> {
    /// emits a tracing error event in case of Err(e)
    ///
    /// this is a convenience function for `.inspect_err(|e| error!(%e))`
    fn trace_err(self) -> Result<T, E>;

    /// emits a tracing error event in case of Err(e)
    ///
    /// this is a convenience function for `.inspect_err(|e| error!(%e, "something went wrong"))`
    fn trace_err_with(self, msg: &'static str) -> Result<T, E>;
}

impl<T, E> TraceError<T, E> for Result<T, E>
where
    E: Display
{
    #[inline(always)]
    fn trace_err(self) -> Result<T, E> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                tracing::error!(%e);
                Err(e)
            }
        }
    }
    #[inline(always)]
    fn trace_err_with(self, msg: &'static str) -> Result<T, E> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                tracing::error!(%e, msg);
                Err(e)
            }
        }
    }
}
