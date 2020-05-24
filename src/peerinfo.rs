use crate::crypto::PeerIdentity;
use crate::service::{self, connect, ServiceConnection};
use crate::transport::{self, TransportServiceInitError};
use crate::{Cfg, Hello, MessageType};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Cursor};

pub mod msg;

/// Get our own identity.
pub async fn get_self_id(cfg: &Cfg) -> Result<PeerIdentity, TransportServiceInitError> {
    let hello = transport::self_hello(cfg).await?;
    Ok(hello.id)
}

/// Struct representing all the currently connected peers.
pub struct PeerInfo {
    conn: ServiceConnection,
}

/// Errors returned by `Peers::next`.
#[derive(Debug, Error)]
pub enum PeerInfoError {
    #[error("The response from the gnunet-peerinfo service was incoherent")]
    InvalidResponse,
    #[error("The peerinfo service sent an unexpected response message type: {typ:?}.")]
    UnexpectedMessageType { typ: u16 },
    #[error(
        "There was an I/O error communicating with the peerinfo service. Specifically: {source}"
    )]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("The service disconnected unexpectedly")]
    Disconnected,
    #[error("Failed to connect to the peerinfo service. Reason: {source}")]
    Connect {
        #[from]
        source: service::ConnectError,
    },
}

impl PeerInfo {
    pub async fn connect(cfg: &Cfg) -> Result<PeerInfo, PeerInfoError> {
        let conn = connect(cfg, "peerinfo").await?;
        Ok(PeerInfo { conn })
    }

    pub async fn get_peer(
        &mut self,
        id: &PeerIdentity,
    ) -> Result<Option<(PeerIdentity, Option<Hello>)>, PeerInfoError> {
        self.conn.send(msg::ListPeer::new(0, *id)).await?;
        let (typ, buf) = self.conn.recv().await?;
        parse_peer(typ, Cursor::new(buf))
    }

    /// Returns a vector of all connected peers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_std::task;
    /// use gnunet::{Cfg, PeerInfo};
    ///
    /// let config = Cfg::default().unwrap();
    /// let peers = task::block_on(async {
    ///     let mut peerinfo = PeerInfo::connect(&config).await.unwrap();
    ///     peerinfo.all_peers().await.unwrap()
    /// });
    /// for (peerid, hello) in peers {
    ///   // do something with peerid
    /// }
    /// ```
    pub async fn all_peers(&mut self) -> Result<Vec<(PeerIdentity, Option<Hello>)>, PeerInfoError> {
        self.conn.send(msg::ListAllPeers::new(0)).await?;
        let mut v = Vec::new();

        loop {
            let (typ, body) = self.conn.recv().await?;
            if let Some(p) = parse_peer(typ, Cursor::new(body))? {
                v.push(p);
            } else {
                break;
            }
        }
        Ok(v)
    }
}

/// Parse some data in `mr` into a tuple of `PeerIdentity` and optionally a `Hello`.
fn parse_peer(
    typ: u16,
    mut mr: Cursor<Vec<u8>>,
) -> Result<Option<(PeerIdentity, Option<Hello>)>, PeerInfoError> {
    match MessageType::from_u16(typ) {
        Some(MessageType::PEERINFO_INFO) => {
            // TODO: if buffer too short, fail with shortmessage error

            // PEERINFO_INFO msg starts with a u32 that's always 0
            if 0 != mr.read_u32::<BigEndian>()? {
                return Err(PeerInfoError::InvalidResponse);
            }

            let id = PeerIdentity::deserialize(&mut mr)?;
            // TODO: if there are more bytes left, parse Hello
            Ok(Some((id, None)))
        }
        Some(MessageType::PEERINFO_INFO_END) => Ok(None),
        _ => Err(PeerInfoError::UnexpectedMessageType { typ }),
    }
}
