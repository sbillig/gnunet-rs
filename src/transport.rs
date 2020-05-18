use crate::hello::HelloDeserializeError;
use crate::peerinfo::PeerIdentity;
use crate::service::{self, MessageHeader, MessageTrait, ReadMessageError};
use crate::{Cfg, Hello, MessageType};
use gj::Promise;
use gjio::Network;
use std::io;

pub struct TransportService {
    //service_reader: ServiceReader,
    //service_writer: ServiceWriter,
    our_hello: Hello,
}

#[derive(Debug, Error)]
pub enum TransportServiceInitError {
    #[error("Expected a HELLO message from the service but received a different message type. Received message type {ty:?} instead.")]
    NonHelloMessage { ty: MessageType },
    #[error("There was an I/O error communicating with the service. Error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Failed to receive a message from the service. Reason: {source}")]
    ReadMessage {
        #[from]
        source: ReadMessageError,
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
    pub fn init(
        cfg: &Cfg,
        network: &Network,
    ) -> Promise<TransportService, TransportServiceInitError> {
        service::connect(cfg, "transport", network)
            .lift()
            .then(move |(sr, mut sw)| {
                let id = PeerIdentity::default();
                let msg = StartMessage::new(0, id);
                sw.send(msg).lift().map(|_| Ok(sr))
            })
            .then(move |mut sr| sr.read_message().lift())
            .map(move |(ty, mut mr)| {
                if ty != MessageType::HELLO {
                    return Err(TransportServiceInitError::NonHelloMessage { ty });
                }
                let hello = Hello::deserialize(&mut mr)?;
                Ok(TransportService { our_hello: hello })
            })
    }
}

pub fn self_hello(cfg: &Cfg, network: &Network) -> Promise<Hello, TransportServiceInitError> {
    TransportService::init(cfg, network).map(|ts| Ok(ts.our_hello))
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
        let len = ::std::mem::size_of::<StartMessage>();
        StartMessage {
            header: MessageHeader {
                len: (len as u16).to_be(),
                tpe: (MessageType::TRANSPORT_START as u16).to_be(),
            },
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
