use crate::service;
use crate::util::{expect_either, Config, ExpectError, Hello, Left, PeerIdentity, Right};
use std::io;

pub mod msg;
use msg::{Info, InfoEnd};

// The peerinfo service can be sent the following message types:
// HELLO - Hello struct - TODO add_peer
// PEERINFO_GET - ListPeer struct
// PEERINFO_GET_ALL - ListAllPeers struct
// PEERINFO_NOTIFY - Notify struct - TODO

// See https://docs.gnunet.org/handbook/gnunet.html#PEERINFO-Subsystem

pub struct Client {
    conn: service::Connection,
}

impl Client {
    pub async fn connect(cfg: &Config) -> Result<Client, PeerInfoError> {
        let conn = service::connect(cfg, "peerinfo").await?;
        Ok(Client { conn })
    }

    pub async fn get_peer(&mut self, id: &PeerIdentity) -> Result<Option<Hello>, PeerInfoError> {
        self.conn.send(&msg::ListPeer::new(false, *id)).await?;

        let (typ, buf) = self.conn.recv().await?;
        match expect_either::<Info, InfoEnd>(typ, &buf)? {
            Left(info) => Ok(Some(info.hello)),
            Right(_) => Ok(None),
        }
    }

    /// Returns a vector of all connected peers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_std::task;
    /// use gnunet::util::Config;
    /// use gnunet::service::peerinfo;
    ///
    /// let config = Config::default().unwrap();
    /// let peers = task::block_on(async {
    ///     let mut pi = peerinfo::Client::connect(&config).await.unwrap();
    ///     pi.all_peers().await.unwrap()
    /// });
    /// for hello in peers {
    ///   // do something with peer hello
    /// }
    /// ```
    pub async fn all_peers(&mut self) -> Result<Vec<Hello>, PeerInfoError> {
        self.conn.send(&msg::ListAllPeers::new(false)).await?;
        let mut v = Vec::new();

        loop {
            let (typ, buf) = self.conn.recv().await?;
            match expect_either::<Info, InfoEnd>(typ, &buf)? {
                Left(info) => v.push(info.hello),
                Right(_) => return Ok(v),
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerInfoError {
    #[error("Unexpected response. Error: {source}")]
    UnexpectedResponse {
        #[from]
        source: ExpectError,
    },
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
