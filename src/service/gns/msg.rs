use super::RecordType;
use crate::crypto::{EcdsaPrivateKey, EcdsaPublicKey};
use crate::message_to_slice;
use crate::util::{MessageHeader, MessageTrait, MessageType};

use std::convert::TryInto;

/// Options for GNS lookups.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LocalOptions {
    /// Default behaviour. Look in the local cache, then in the DHT.
    Default = 0,
    /// Do not look in the DHT, keep the request to the local cache.
    NoDHT = 1,
    /// For domains controlled by our master zone only look in the cache. Otherwise look in the
    /// cache, then in the DHT.
    LocalMaster = 2,
}

/// Packed struct representing GNUNET_GNS_ClientLookupMessage.
#[repr(C, packed)]
pub struct Lookup {
    header: MessageHeader,
    id: u32,
    zone: EcdsaPublicKey,
    options: i16,     // LocalOptions
    have_key: i16,    // 0 or 1
    record_type: i32, // RecordType
    shorten_key: EcdsaPrivateKey,
    // followed by 0-terminated name to look up
}

impl Lookup {
    pub fn new(
        id: u32,
        zone: EcdsaPublicKey,
        options: LocalOptions,
        shorten: Option<EcdsaPrivateKey>,
        record_type: RecordType,
        name: &str,
    ) -> Self {
        let msg_len = (std::mem::size_of::<Self>() + name.len() + 1)
            .try_into()
            .unwrap();
        Lookup {
            header: MessageHeader::new(msg_len, MessageType::GNS_LOOKUP),
            id: id.to_be(),
            zone,
            options: (options as i16).to_be(),
            have_key: (shorten.is_some() as i16).to_be(),
            record_type: (record_type as i32).to_be(),
            shorten_key: match shorten {
                Some(x) => x,
                None => EcdsaPrivateKey::zeros(),
            },
        }
    }
}

impl MessageTrait for Lookup {
    // Note that this does not include the 0-terminated string.
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(Lookup, self)
    }
}
