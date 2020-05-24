use crate::crypto::PeerIdentity;
use crate::hello::HelloDeserializeError;
use crate::service::{self, MessageHeader, MessageTrait};
use crate::{Cfg, Hello, MessageType};
use std::convert::TryInto;
use std::io::{self, Cursor};

pub struct TransportService {
    //service_reader: ServiceReader,
    //service_writer: ServiceWriter,
    our_hello: Hello,
}

#[derive(Debug, Error)]
pub enum TransportServiceInitError {
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

impl TransportService {
    pub async fn connect(cfg: &Cfg) -> Result<TransportService, TransportServiceInitError> {
        let mut conn = service::connect(cfg, "transport").await?;
        let id = PeerIdentity::default();
        let msg = StartMessage::new(0, id);
        conn.send(msg).await?;
        let (typ, body) = conn.recv().await?;
        match MessageType::from_u16(typ) {
            Some(MessageType::HELLO) => {
                let mut mr = Cursor::new(body);
                let our_hello = Hello::deserialize(&mut mr)?;
                Ok(TransportService { our_hello })
            }
            _ => Err(TransportServiceInitError::NonHelloMessage { typ }),
        }
    }
}

pub async fn self_hello(cfg: &Cfg) -> Result<Hello, TransportServiceInitError> {
    let ts = TransportService::connect(cfg).await?;
    Ok(ts.our_hello)
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
