use crate::service;
use crate::util::message::{expect, ExpectError};
use crate::util::{Config, Hello, PeerIdentity};
use std::io;

pub mod msg;
pub mod tcp;

pub struct Client {
    conn: service::Connection,
    pub our_hello: Hello,
}

impl Client {
    pub async fn connect(cfg: &Config) -> Result<Client, ConnectError> {
        let mut conn = service::connect(cfg, "transport").await?;
        // TODO: are we supposed to send the null id here?
        conn.send(&msg::Start::new(0, PeerIdentity::default()))
            .await?;

        let (typ, buf) = conn.recv().await?;
        let our_hello = expect::<Hello>(typ, &buf)?;
        Ok(Client { conn, our_hello })
    }
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("Expected a HELLO message. Error: {source}")]
    NonHelloMessage {
        #[from]
        source: ExpectError,
    },
    #[error("There was an I/O error communicating with the service. Error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Failed to connect to the transport service. Reason: {source}")]
    Connect {
        #[from]
        source: service::ConnectError,
    },
}
