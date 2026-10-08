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
    /// emits a tracing error event in case of Err(e)
    ///
    /// this is a convenicne function for `.inspect_err(|e| error!(%e))`
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
