//! Module for connecting to and querying the GNUnet identity service.

use byteorder::{BigEndian, ReadBytesExt};
use num::ToPrimitive;
use std::collections::HashMap;
use std::fmt;
use std::io;

use crate::crypto::{EcdsaPrivateKey, EcdsaPublicKey, HashCode};
use crate::util::{Config, MessageHeader, MessageTrait, MessageType};
use crate::{message_to_slice, service};

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
        Ego { sk, name: None, id }
    }

    /// Get the public key of an ego.
    pub fn get_public_key(&self) -> EcdsaPublicKey {
        self.sk.get_public()
    }

    /// Get the private key of an ego.
    pub fn get_private_key(&self) -> EcdsaPrivateKey {
        self.sk
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
    conn: service::Connection,
}

/// Errors returned by `IdentityService::connect`
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("Failed to connect to the service. Reason: {source}")]
    Connect {
        #[from]
        source: service::ConnectError,
    },
    #[error("The service disconnected unexpectedly")]
    Disconnected,
    #[error(
        "An I/O error occured while communicating with the identity service. Specifically: {source}"
    )]
    Io {
        #[from]
        source: io::Error,
    },
}

#[derive(Debug, Error)]
pub enum UpdateStreamError {
    #[error("The service responded with a name containing invalid utf-8 during initial exchange. *(It is a bug to see this error)*. Utf8-error: {source}")]
    InvalidName {
        #[from]
        source: std::str::Utf8Error,
    },
    #[error("Received an unexpected message from the service during initial exchange. *(It is a bug to see this error)*. Message type {typ:?} was not expected.")]
    UnexpectedMessageType { typ: u16 },
    #[error(
        "An I/O error occured while communicating with the identity service. Specifically: {source}"
    )]
    Io {
        #[from]
        source: io::Error,
    },
}

/// Errors returned by `IdentityService::get_default_ego`
#[derive(Debug, Error)]
pub enum GetDefaultEgoError {
    #[error(
        "The name of the service was too long. \"{name}\" is too long to be the name of a service."
    )]
    NameTooLong { name: String },
    #[error(
        "An I/O error occured while communicating with the identity service. Specifically: {source}"
    )]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("The service responded with an error message. Error: \"{response}\"")]
    ServiceResponse { response: String },
    #[error("The service responded with an error message but the message contained invalid utf-8. Utf8-error: {source}")]
    MalformedErrorResponse {
        #[from]
        source: std::str::Utf8Error,
    },
    #[error("Failed to receive the identity name from the service")]
    ReceiveName,
    #[error("Failed to connect to the identity service. Reason: {source}")]
    Connect {
        #[from]
        source: ConnectError,
    },
    #[error("The service response was incoherent. You should file a bug-report if you encounter this error.")]
    InvalidResponse,
    #[error("The service disconnected unexpectedly")]
    Disconnected,
}

impl IdentityService {
    /// Connect to the identity service.
    ///
    /// Returns either a promise of a handle to the identity service or a `ServiceConnectError`.
    /// `cfg` contains the configuration to use to connect to the service.
    pub async fn connect(cfg: &Config) -> Result<IdentityService, ConnectError> {
        let conn = service::connect(cfg, "identity").await?;
        Ok(IdentityService { conn })
    }

    // TODO: return Stream
    pub async fn get_update_stream(&mut self) -> Result<HashMap<HashCode, Ego>, UpdateStreamError> {
        // Service response:
        //   N IDENTITY_UPDATE msgs.
        //   Last message in initial N have end_of_list == true, name_len == 0.
        //   Service will continue to send IDENTITY_UPDATE msgs periodically.

        self.conn.send(StartMessage::new()).await?;
        let mut egos: HashMap<HashCode, Ego> = HashMap::new();
        loop {
            let (typ, buf) = self.conn.recv().await?;
            if MessageType::from_u16(typ) != Some(MessageType::IDENTITY_UPDATE) {
                return Err(UpdateStreamError::UnexpectedMessageType { typ });
            }
            if let Some(ego) = parse_update_msg(&buf)? {
                egos.insert(ego.id.clone(), ego);
            } else {
                // end of list
                break;
            }
        }
        Ok(egos)
    }

    /// Get the default identity associated with a service.
    pub async fn get_default_ego(&mut self, name: &str) -> Result<Ego, GetDefaultEgoError> {
        // Service response:
        //   If default is found, one IDENTITY_SET_DEFAULT msg.
        //   Else service responds with IDENTITY_RESULT_CODE msg,
        //     with result_code == 1, and cstr message.

        let msg = GetDefaultMessage::new(name)?;
        self.conn.send_with_str(msg, name).await?;
        let (typ, body) = self.conn.recv().await?;

        match MessageType::from_u16(typ) {
            Some(MessageType::IDENTITY_RESULT_CODE) => {
                let (mut code, msg) = (&body).split_at(4);
                let _errcode = code.read_u32::<BigEndian>()?;
                let errmsg = if msg.len() == 0 {
                    String::new()
                } else {
                    std::str::from_utf8(&msg[..msg.len() - 1])?.to_string()
                };
                Err(GetDefaultEgoError::ServiceResponse { response: errmsg })
            }
            Some(MessageType::IDENTITY_SET_DEFAULT) => parse_set_default_msg(&body),
            _ => Err(GetDefaultEgoError::InvalidResponse), // TODO: better err
        }
    }
}

fn parse_update_msg<B: AsRef<[u8]>>(body: B) -> Result<Option<Ego>, UpdateStreamError> {
    let buf = body.as_ref();
    let (head, buf) = buf.split_at(4);
    let name_len = (&head[0..2]).read_u16::<BigEndian>()? as usize;
    let eol = (&head[2..]).read_u16::<BigEndian>()?;
    if eol != 0 {
        return Ok(None);
    }

    let (key, buf) = buf.split_at(32);

    let sk = EcdsaPrivateKey::from_bytes(&key)?;
    let name = std::str::from_utf8(&buf[..name_len])?.to_string();
    let id = sk.get_public().hash();
    Ok(Some(Ego {
        sk,
        name: Some(name),
        id,
    }))
}

fn parse_set_default_msg<B: AsRef<[u8]>>(body: B) -> Result<Ego, GetDefaultEgoError> {
    // body is:
    //  name_len: u16 // includes trailing null
    //  reserved: u16
    //  private_key: EcdsaPrivateKey
    //  followed by name_len bytes

    let buf = body.as_ref();
    let (head, buf) = buf.split_at(4);
    let name_len = (&head[..2]).read_u16::<BigEndian>()? as usize;
    let reserved = (&head[2..]).read_u16::<BigEndian>()?;
    if reserved != 0 {
        return Err(GetDefaultEgoError::InvalidResponse);
    }
    let (key, buf) = buf.split_at(32);
    let sk = EcdsaPrivateKey::from_bytes(&key)?;
    let name = std::str::from_utf8(&buf[..name_len - 1])?.to_string();
    let id = sk.get_public().hash();
    Ok(Ego {
        sk,
        name: Some(name),
        id,
    })
}

/// Packed struct representing the initial message sent to the identity service.
#[repr(C, packed)]
struct StartMessage {
    header: MessageHeader,
}

impl StartMessage {
    fn new() -> StartMessage {
        StartMessage {
            header: MessageHeader::new(4, MessageType::IDENTITY_START),
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
        use std::mem;
        let name_len = name.len();
        let msg_len = match (mem::size_of::<GetDefaultMessage>() + name_len + 1).to_u16() {
            Some(l) => l,
            None => {
                return Err(GetDefaultEgoError::NameTooLong {
                    name: name.to_string(),
                })
            }
        };

        Ok(GetDefaultMessage {
            header: MessageHeader::new(msg_len, MessageType::IDENTITY_GET_DEFAULT),
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
