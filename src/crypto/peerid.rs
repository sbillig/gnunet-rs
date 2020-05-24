use super::EddsaPublicKey;
use crate::util::strings::{data_to_string, string_to_data};
use std::fmt;
use std::io::{self, Read, Write};
use std::str::FromStr;

/// The identity of a GNUnet peer.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PeerIdentity {
    public_key: EddsaPublicKey,
}

impl PeerIdentity {
    /// Deserializes into PeerIdentity from a reader, the reader should have 32 bytes available.
    pub fn deserialize<R>(r: &mut R) -> Result<PeerIdentity, io::Error>
    where
        R: Read,
    {
        let mut public_key = EddsaPublicKey::default();
        r.read_exact(&mut public_key.q_y[..])?;
        Ok(PeerIdentity { public_key })
    }

    /// Serializes and writes the identity into a writer.
    pub fn serialize<T>(&self, w: &mut T) -> Result<(), io::Error>
    where
        T: Write,
    {
        w.write_all(&self.public_key.q_y[..])
    }
}

/// Error generated when attempting to parse a PeerIdentity
#[derive(Debug, Error)]
pub enum PeerIdentityFromStrError {
    #[error("Failed to parse the string as a PeerIdentity")]
    ParsingFailed,
}

impl FromStr for PeerIdentity {
    type Err = PeerIdentityFromStrError;

    fn from_str(s: &str) -> Result<PeerIdentity, PeerIdentityFromStrError> {
        let mut public_key = EddsaPublicKey::default();
        if string_to_data(s, &mut public_key.q_y) {
            Ok(PeerIdentity { public_key })
        } else {
            Err(PeerIdentityFromStrError::ParsingFailed)
        }
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        assert!(52usize == (std::mem::size_of_val(&self.public_key.q_y) * 8 + 4) / 5);
        let res = data_to_string(&self.public_key.q_y);
        fmt::Display::fmt(res.as_str(), f)
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
