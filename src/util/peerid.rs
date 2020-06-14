use crate::crypto::EddsaPublicKey;
use crate::util::strings::{crockford_base32_decode, crockford_base32_encode};
use std::fmt;
use std::str::FromStr;
use zerocopy::{AsBytes, FromBytes};

/// The identity of a GNUnet peer.
#[repr(C)]
#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
pub struct PeerIdentity {
    public_key: EddsaPublicKey,
}

/// Error generated when attempting to parse a PeerIdentity
#[derive(Debug, Error)]
pub enum PeerIdentityFromStrError {
    #[error("Failed to parse the string as a PeerIdentity")]
    DecodeFailed,

    #[error("Incorrect PeerIdentity data length: {len}.")]
    WrongLen { len: usize },
}

impl FromStr for PeerIdentity {
    type Err = PeerIdentityFromStrError;

    fn from_str(s: &str) -> Result<PeerIdentity, PeerIdentityFromStrError> {
        let b = crockford_base32_decode(s).ok_or(PeerIdentityFromStrError::DecodeFailed)?;
        let public_key = EddsaPublicKey::from_bytes(&b)
            .ok_or(PeerIdentityFromStrError::WrongLen { len: b.len() })?;
        Ok(PeerIdentity { public_key })
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &crockford_base32_encode(&self.public_key.bytes()))
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &crockford_base32_encode(self.public_key.bytes()))
    }
}
