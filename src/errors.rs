use thiserror::Error;

// pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
}

pub trait TraceErr<T, E> {
    /// simple helper to emit a tracing error when Err(e)
    fn trace_err(self) -> Result<T, E>;
}

impl<T, E> TraceErr<T, E> for Result<T, E>
where
    E: std::error::Error,
{
    fn trace_err(self) -> Result<T, E> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                tracing::error!(%e);
                Err(e)
            }
        }
    }
}
