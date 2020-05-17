use gj::Promise;
use gjio::Network;
use hello::HelloDeserializeError;
use ll;
use service::{self, MessageHeader, MessageTrait, ReadMessageError};
use std::io;
use Cfg;
use Hello;

pub struct TransportService {
    //service_reader: ServiceReader,
    //service_writer: ServiceWriter,
    our_hello: Hello,
}

#[derive(Debug, Error)]
pub enum TransportServiceInitError {
    #[error("Expected a HELLO message from the service but received a different message type. Received message type {ty} instead.")]
    NonHelloMessage { ty: u16 },
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
                let id = ll::Struct_GNUNET_PeerIdentity {
                    public_key: ll::Struct_GNUNET_CRYPTO_EddsaPublicKey { q_y: [0; 32] },
                };
                let msg = StartMessage::new(0, id);
                sw.send(msg).lift().map(|_| Ok(sr))
            })
            .then(move |mut sr| sr.read_message().lift())
            .map(move |(ty, mut mr)| {
                if ty != ll::GNUNET_MESSAGE_TYPE_HELLO {
                    return Err(TransportServiceInitError::NonHelloMessage { ty: ty });
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
    myself: ll::Struct_GNUNET_PeerIdentity,
}

impl StartMessage {
    fn new(options: u32, peer: ll::Struct_GNUNET_PeerIdentity) -> StartMessage {
        let len = ::std::mem::size_of::<StartMessage>();
        StartMessage {
            header: MessageHeader {
                len: (len as u16).to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_TRANSPORT_START.to_be(),
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
