use std::string;
use std::collections::HashMap;
use std::io::{self, Read, Cursor};
use std::fmt;
use std::rc::*;
use byteorder::{BigEndian, ReadBytesExt};
use num::ToPrimitive;

use ll;
use EcdsaPrivateKey;
use EcdsaPublicKey;
use HashCode;
use service::{self, ServiceReader, ServiceWriter, MessageHeader, MessageTrait};
use configuration::Cfg;
use util::{ReadCString, ReadCStringError, ReadCStringWithLenError};

use gj::{Promise};
use gjio::{Network};

/// A GNUnet identity.
///
/// An ego consists of a public/private key pair and a name.
#[derive(Clone)]
pub struct Ego {
    sk: EcdsaPrivateKey,
    name: Option<String>,
    id: HashCode,
}

impl Ego {
    /// Get a copy of the global, anonymous ego.
    pub fn anonymous() -> Ego {
        let sk = EcdsaPrivateKey::anonymous();
        let id = sk.get_public().hash();
        Ego {
            sk: sk,
            name: None,
            id: id,
        }
    }

    /// Get the public key of an ego.
    pub fn get_public_key(&self) -> EcdsaPublicKey {
        self.sk.get_public()
    }

    /// Get the private key of an ego.
    pub fn get_private_key(&self) -> EcdsaPrivateKey {
        self.sk.clone()
    }

    /// Get the name of an ego.
    pub fn get_name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Get the unique id of an ego. This is a hash of the ego's public key.
    pub fn get_id(&self) -> &HashCode {
        &self.id
    }
}

impl fmt::Display for Ego {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self.name {
            Some(ref n) => &**n,
            None => "<anonymous>",
        };
        write!(f, "{} ({})", name, self.id)
    }
}

/// A handle to the identity service.
pub struct IdentityService {
    service_reader: ServiceReader,
    service_writer: ServiceWriter,
    egos: Rc<HashMap<HashCode, Ego>>, // egos is only modified at connect
}

/// Errors returned by `IdentityService::connect`
error_def! ConnectError {
    Connect { #[from] cause: service::ConnectError }
        => "Failed to connect to the service" ("Reason: {}", cause),
    Disconnected
        => "The service disconnected unexpectedly",
    Io { #[from] cause: io::Error }
        => "An I/O error occured while communicating with the identity service" ("Specifically: {}", cause),
    ReadMessage { #[from] cause: service::ReadMessageError }
        => "Failed to read a message from the server" ("Specifically: {}", cause),
    InvalidName { #[from] cause: string::FromUtf8Error }
        => "The service responded with a name containing invalid utf-8 during initial exchange. *(It is a bug to see this error)*" ("Utf8-error: {}", cause),
    UnexpectedMessageType { ty: u16 }
        => "Received an unexpected message from the service during initial exchange. *(It is a bug to see this error)*" ("Message type {} was not expected.", ty)
}

/// Errors returned by `IdentityService::get_default_ego`
error_def! GetDefaultEgoError {
    NameTooLong { name: String }
        => "The name of the service was too long" ("\"{}\" is too long to be the name of a service.", name),
    Io { #[from] cause: io::Error }
        => "An I/O error occured while communicating with the identity service" ("Specifically: {}", cause),
    ReadMessage { #[from] cause: service::ReadMessageError }
        => "Failed to read a message from the server" ("Specifically: {}", cause),
    ServiceResponse { response: String }
        => "The service responded with an error message" ("Error: \"{}\"", response),
    MalformedErrorResponse { #[from] cause: string::FromUtf8Error }
        => "The service responded with an error message but the message contained invalid utf-8" ("Utf8-error: {}", cause),
    ReceiveName { #[from] cause: ReadCStringWithLenError }
        => "Failed to receive the identity name from the service" ("Reason: {}", cause),
    Connect { #[from] cause: ConnectError }
        => "Failed to connect to the identity service" ("Reason: {}", cause),
    InvalidResponse
        => "The service response was incoherent. You should file a bug-report if you encounter this error.",
    Disconnected
        => "The service disconnected unexpectedly",
}

impl IdentityService {
    /// Connect to the identity service.
    ///
    /// Returns either a promise of a handle to the identity service or a `ServiceConnectError`.
    /// `cfg` contains the configuration to use to connect to the service.
    pub fn connect(cfg: &Cfg, network: &Network) -> Promise<IdentityService, ConnectError> {
      /*
      let (get_tx, get_rx) = channel::<(String, Sender<Option<Ego>>>();
      let service = try!(Service::connect("identity", move |&mut: tpe: u16, mut reader: LimitReader<UnixStream>| -> ProcessMessageResult {
        loop {

        }
      }));
      */
      // let (mut service_reader, mut service_writer) = service::connect(cfg, "identity", network);
        service::connect(cfg, "identity", network)
            .lift()
            .then(|(sr, mut sw)| {
                sw.send(StartMessage::new())
                    .lift()
                    .map(move |()| { Ok((sr, sw)) })
            })
            .then(|(sr, sw)| {
                let egos: HashMap<HashCode, Ego> = HashMap::new();
                IdentityService::parse_egos(sr, egos)
                    .map(|(sr, egos)| {
                        Ok(IdentityService {
                            service_reader: sr,
                            service_writer: sw,
                            egos: Rc::new(egos),
                        })
                    })
            })
    }

    /// This recursive function reads data from the ServiceReader `sr`
    /// and attempts to parse the result into egos.
    fn parse_egos<'a>(mut sr: ServiceReader, mut egos: HashMap<HashCode, Ego>)
                      -> Promise<(ServiceReader, HashMap<HashCode, Ego>), ConnectError> {
        sr.read_message()
            .lift()
            .then(|(tpe, mut mr)| {
                match tpe {
                    ll::GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE => {
                        let name_len = pry!(mr.read_u16::<BigEndian>());
                        let eol = pry!(mr.read_u16::<BigEndian>());
                        if eol != 0 {
                            return Promise::ok((sr, egos));
                        };
                        let sk = pry!(EcdsaPrivateKey::deserialize(&mut mr));
                        let mut v: Vec<u8> = Vec::with_capacity(name_len as usize);
                        for r in mr.bytes() {
                            let b = pry!(r);
                            if b == 0u8 {
                                break;
                            }
                            v.push(b)
                        };
                        let name = match String::from_utf8(v) {
                            Ok(n)   => n,
                            Err(v)  => return Promise::err(ConnectError::InvalidName { cause: v }),
                        };
                        let id = sk.get_public().hash();
                        egos.insert(id.clone(), Ego {
                            sk: sk,
                            name: Some(name),
                            id: id,
                        });
                        return IdentityService::parse_egos(sr, egos)
                    },
                    _ => return Promise::err(ConnectError::UnexpectedMessageType { ty: tpe }),
                };
            })
    }

    /// Returns a promise to the default identity associated with a service.
    ///
    /// # Example
    ///
    /// Get the ego for the default master zone.
    ///
    /// ```rust
    /// use gnunet::{Cfg, IdentityService};
    /// use gnunet::util::async;
    ///
    /// let mut event_port = async::EventPort::new().unwrap();
    /// let network = event_port.get_network();
    /// let config = Cfg::default().unwrap();
    ///
    /// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
    ///     let ego_promise = IdentityService::connect(&config, &network).lift()
    ///                         .then(|mut is| { is.get_default_ego("gns-master") });
    ///     let ego = ego_promise.wait(wait_scope, &mut event_port);
    ///     Ok(())
    /// }).expect("top_level");
    /// ```
    pub fn get_default_ego(&mut self, name: &'static str) -> Promise<Ego, GetDefaultEgoError> {
        let msg = pry!(GetDefaultMessage::new(name));
        let mut sr = self.service_reader.clone();
        let egos = self.egos.clone();
        self.service_writer.send_with_str(msg, name)
            .lift()
            .then(move |_| {
                sr.read_message()
                    .lift()
                    .map(move |(tpe, mr)| {
                        match IdentityService::parse_identity(egos, name, tpe, mr) {
                            Ok(ego) => Ok(ego),
                            Err(e)  => Err(e),
                        }
                    })
            })
            .lift()
    }

    /// Returns an identity by parsing data from `mr`.
    fn parse_identity(rc_egos: Rc<HashMap<HashCode, Ego>>, name: &str, tpe: u16, mut mr: Cursor<Vec<u8>>)
                             -> Result<Ego, GetDefaultEgoError> {
        let egos = rc_egos.as_ref();
        match tpe {
            ll::GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE => {
                try!(mr.read_u32::<BigEndian>());
                match mr.read_c_string() {
                    Err(e) => match e {
                        ReadCStringError::Io { cause }       => Err(GetDefaultEgoError::Io { cause: cause }),
                        ReadCStringError::FromUtf8 { cause } => Err(GetDefaultEgoError::MalformedErrorResponse { cause: cause }),
                        ReadCStringError::Disconnected       => Err(GetDefaultEgoError::Disconnected),
                    },
                    Ok(s)  => Err(GetDefaultEgoError::ServiceResponse { response: s }),
                }
            },
            ll::GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT => match try!(mr.read_u16::<BigEndian>()) {
                0 => Err(GetDefaultEgoError::InvalidResponse),
                reply_name_len => {
                    let zero = try!(mr.read_u16::<BigEndian>());
                    match zero {
                        0 => {
                            let sk = try!(EcdsaPrivateKey::deserialize(&mut mr));
                            let s: String = try!(mr.read_c_string_with_len((reply_name_len - 1) as usize));
                            match &s[..] == name {
                                true  => {
                                    let id = sk.get_public().hash();
                                    Ok(egos[&id].clone())
                                },
                                false => Err(GetDefaultEgoError::InvalidResponse),
                            }
                        },
                        _ => Err(GetDefaultEgoError::InvalidResponse),
                    }
                },
            },
            _ => Err(GetDefaultEgoError::InvalidResponse),
        }
    }
}

/// Errors returned by `identity::get_default_ego`
error_def! ConnectGetDefaultEgoError {
    GetDefaultEgo { #[from] cause: GetDefaultEgoError }
        => "Ego lookup failed" ("Reason: {}", cause),
    Connect { #[from] cause: ConnectError }
        => "Failed to connect to the service and perform initialization" ("Reason: {}", cause),
    Io { #[from] cause: io::Error }
        => "An I/O error occured while communicating with the identity service" ("Specifically: {}", cause),
}

/// Get the default identity associated with a service.
///
/// # Example
///
/// ```rust
/// use gnunet::Cfg;
/// use gnunet::util::async;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = async::EventPort::new().unwrap();
/// let network = event_port.get_network();
///
/// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let ego_promise = gnunet::get_default_ego(&config, "gns-master", &network);
///     let ego = ego_promise.wait(wait_scope, &mut event_port);
///     Ok(())
/// }).expect("top_level");
/// ```
///
/// # Note
///
/// This a convenience function that connects to the identity service, does the query, then
/// disconnects. If you want to do multiple queries you should connect to the service with
/// `IdentityService::connect` then use that handle to do the queries.
pub fn get_default_ego(
    cfg: &Cfg,
    name: &'static str,
    network: &Network) -> Promise<Ego, ConnectGetDefaultEgoError> {
    IdentityService::connect(cfg, network)
        .lift()
        .then(move |mut is| {
            is.get_default_ego(name)
        })
        .lift()
}

/// Packed struct representing the initial message sent to the identity service.
#[repr(C, packed)]
struct StartMessage {
    header: MessageHeader,
}

impl StartMessage {
    fn new () -> StartMessage {
        StartMessage {
            header: MessageHeader {
                len: 4u16.to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_IDENTITY_START.to_be(),
            }
        }
    }
}

impl MessageTrait for StartMessage {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(StartMessage, self)
    }
}

/// Packed struct representing GNUNET_IDENTITY_GetDefaultMessage,
/// note that it must be followed by a 0-terminated string.
#[repr(C, packed)]
struct GetDefaultMessage {
    header: MessageHeader,
    name_len: u16,
    reserved: u16, // always zero
    // followed by 0-terminated string
}

impl GetDefaultMessage {
    fn new(name: &str) -> Result<GetDefaultMessage, GetDefaultEgoError> {
        let name_len = name.len();
        let msg_len = match (8 + name_len + 1).to_u16() {
            Some(l) => l,
            None    => return Err(GetDefaultEgoError::NameTooLong { name: name.to_string() }),
        };

        Ok(GetDefaultMessage {
            header: MessageHeader {
                len: (msg_len as u16).to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT.to_be(),
            },
            name_len: ((name_len + 1) as u16).to_be(),
            reserved: 0u16.to_be(),
        })
    }
}

impl MessageTrait for GetDefaultMessage {
    // Note that this does not include the 0-terminated string.
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(GetDefaultMessage, self)
    }
}

