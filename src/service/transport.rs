use crate::util::{
    Config, Hello, HelloDeserializeError, MessageHeader, MessageTrait, MessageType, PeerIdentity,
};
use crate::{message_to_slice, service};
use std::convert::TryInto;
use std::io::{self, Cursor};

pub struct Client {
    conn: service::Connection,
    our_hello: Hello,
}

impl Client {
    pub async fn connect(cfg: &Config) -> Result<Client, ConnectError> {
        let mut conn = service::connect(cfg, "transport").await?;
        conn.send(StartMessage::new(0, PeerIdentity::default()))
            .await?;

        let (typ, body) = conn.recv().await?;
        match MessageType::from_u16(typ) {
            Some(MessageType::HELLO) => {
                let our_hello = Hello::deserialize(&mut Cursor::new(body))?;
                Ok(Client { conn, our_hello })
            }
            _ => Err(ConnectError::NonHelloMessage { typ }),
        }
    }
}

pub async fn self_hello(cfg: &Config) -> Result<Hello, ConnectError> {
    let ts = Client::connect(cfg).await?;
    Ok(ts.our_hello)
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("Expected a HELLO message from the service but received a different message type. Received message type {typ:?} instead.")]
    NonHelloMessage { typ: u16 },
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
    #[error("Failed to serialize the hello message from the service. Reason {source}")]
    HelloDeserialize {
        #[from]
        source: HelloDeserializeError,
    },
}

/// Representing StartMessage in transport.
#[repr(C, packed)]
struct StartMessage {
    header: MessageHeader,
    options: u32,
    myself: PeerIdentity,
}

impl StartMessage {
    fn new(options: u32, peer: PeerIdentity) -> StartMessage {
        let len = std::mem::size_of::<StartMessage>().try_into().unwrap();
        StartMessage {
            header: MessageHeader::new(len, MessageType::TRANSPORT_START),
            options: options.to_be(),
            myself: peer,
        }
    }
}

impl MessageTrait for StartMessage {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(StartMessage, self)
    }
}
