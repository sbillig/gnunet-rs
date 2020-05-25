//! Module for connecting to and querying the GNUnet GNS service.

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Cursor};
use thiserror::Error;

pub use self::record::*;
use crate::crypto::{EcdsaPrivateKey, EcdsaPublicKey};
use crate::service;
use crate::util::{Config, MessageType};

pub mod msg;
pub mod record;
pub use msg::LocalOptions;

pub const GNUNET_DNSPARSER_MAX_NAME_LENGTH: u16 = 253;

/// A handle to a locally-running instance of the GNS daemon.
pub struct Client {
    conn: service::Connection,
    lookup_id: u32,
}

/// Possible errors returned by the GNS lookup functions.
#[derive(Debug, Error)]
pub enum LookupError {
    #[error("The received message type '{typ:?}' is invalid.")]
    InvalidType { typ: u16 },
    #[error("The domain name '{name}' is too long to lookup.")]
    NameTooLong { name: String },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}

impl Client {
    /// Connect to the GNS service.
    ///
    /// Returns either a promise to the GNS service or a `service::ConnectError`. `cfg` contains the
    /// configuration to use to connect to the service.
    pub async fn connect(cfg: &Config) -> Result<Client, service::ConnectError> {
        let conn = service::connect(cfg, "gns").await?;
        Ok(Client { conn, lookup_id: 0 })
    }

    /// Lookup a vector of GNS records.
    /// A promise of the result is returned.
    ///
    /// If `shorten` is not `None` then the result is added to the given shorten zone.
    ///
    /// # Example
    ///
    pub async fn lookup(
        &mut self,
        name: &str,
        zone: EcdsaPublicKey,
        record_type: RecordType,
        options: LocalOptions,
        shorten: Option<EcdsaPrivateKey>,
    ) -> Result<Vec<Record>, LookupError> {
        if name.len() > GNUNET_DNSPARSER_MAX_NAME_LENGTH as usize {
            return Err(LookupError::NameTooLong {
                name: name.to_string(),
            });
        };

        let id = self.lookup_id;
        self.lookup_id += 1;
        let msg = msg::Lookup::new(id, zone, options, shorten, record_type, &name);

        self.conn.send_with_str(msg, &name).await?;
        let (typ, buf) = self.conn.recv().await?;

        match MessageType::from_u16(typ) {
            Some(MessageType::GNS_LOOKUP_RESULT) => {
                let mut reader = Cursor::new(buf);
                let _id = reader.read_u32::<BigEndian>()?;

                let rd_count = reader.read_u32::<BigEndian>()? as usize;
                let mut records = Vec::with_capacity(rd_count);
                for _ in 0..rd_count {
                    records.push(Record::deserialize(&mut reader)?);
                }
                Ok(records)
            }
            _ => Err(LookupError::InvalidType { typ }),
        }
    }
}

/// Errors returned by `gns::lookup`.
#[derive(Debug, Error)]
pub enum ConnectLookupError {
    #[error("Failed to connect to the GNS service. Reason: {source}")]
    Connect {
        #[from]
        source: service::ConnectError,
    },
    #[error("Failed to perform the lookup.. Reason: {source}")]
    Lookup {
        #[from]
        source: LookupError,
    },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}
