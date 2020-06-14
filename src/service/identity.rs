//! Module for connecting to and querying the GNUnet identity service.

use crate::crypto::{EcdsaPrivateKey, EcdsaPublicKey, HashCode};
use crate::service;
use crate::util::message::{expect_either, Left, Right};
use crate::util::Config;

use std::collections::HashMap;
use std::fmt;
use std::io;
mod msg;
pub use msg::*;

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
pub struct Client {
    conn: service::Connection,
}

/// Errors returned by `Client::connect`
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

/// Errors returned by `Client::get_default_ego`
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

impl Client {
    /// Connect to the identity service.
    ///
    /// Returns either a promise of a handle to the identity service or a `ServiceConnectError`.
    /// `cfg` contains the configuration to use to connect to the service.
    pub async fn connect(cfg: &Config) -> Result<Client, ConnectError> {
        let conn = service::connect(cfg, "identity").await?;
        Ok(Client { conn })
    }

    // TODO: return Stream
    pub async fn get_update_stream(&mut self) -> Result<HashMap<HashCode, Ego>, UpdateStreamError> {
        // Service response:
        //   N IDENTITY_UPDATE msgs.
        //   Last message in initial N have end_of_list == true, name_len == 0.
        //   Service will continue to send IDENTITY_UPDATE msgs periodically.

        // self.conn.send(&Lookup::new()).await?;
        todo!();
    }

    /// Get the default identity associated with a service.
    pub async fn get_default_ego(&mut self, name: &str) -> Result<Ego, GetDefaultEgoError> {
        // Service response:
        //   If default is found, one IDENTITY_SET_DEFAULT msg.
        //   Else service responds with IDENTITY_RESULT_CODE msg,
        //     with result_code == 1, and cstr message.

        // TODO: check name len here
        let msg = GetDefault::new(name).unwrap();
        self.conn.send_compound(&msg).await?;

        let (typ, buf) = self.conn.recv().await?;
        match expect_either::<ResultCode<String>, SetDefault<String>>(typ, &buf).unwrap() // XXX
        {
            Left(ResultCode { err_msg, .. }) => {
                Err(GetDefaultEgoError::ServiceResponse { response: err_msg })
            }
            Right(s) => {
		let (name, sk) = s.into_name_and_key();
		let id = sk.get_public().hash();
		Ok(Ego {
		    sk,
		    name: Some(name),
		    id
		})
	    }
        }
    }
}
