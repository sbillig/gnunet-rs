use std::convert::TryFrom;
use std::fmt::{self, Debug, Formatter};
use std::str::FromStr;

use crate::crypto::HashCode;
use crate::util::serial::*;
use crate::util::strings::{crockford_base32_decode, crockford_base32_encode};

/// A 256bit ECDSA public key.
#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct EcdsaPublicKey {
    data: [u8; 32],
}

impl EcdsaPublicKey {
    /// Compute the hash of this key.
    pub fn hash(&self) -> HashCode {
        HashCode::from_buffer(&self.data)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let data = <[u8; 32]>::try_from(b).ok()?;
        Some(Self { data })
    }
}

/// Error generated when attempting to parse an ecdsa public key
#[derive(Debug, Error)]
pub enum EcdsaPublicKeyFromStrError {
    #[error("Failed to parse the string as an ecdsa public key")]
    DecodeFailed,

    #[error("Incorrect ecdsa public key data length: {len}.")]
    WrongLen { len: usize },
}

impl FromStr for EcdsaPublicKey {
    type Err = EcdsaPublicKeyFromStrError;
    fn from_str(s: &str) -> Result<Self, EcdsaPublicKeyFromStrError> {
        let b = crockford_base32_decode(s).ok_or(EcdsaPublicKeyFromStrError::DecodeFailed)?;
        Self::from_bytes(&b).ok_or(EcdsaPublicKeyFromStrError::WrongLen { len: b.len() })
    }
}

impl Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", &crockford_base32_encode(&self.data))
    }
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", &crockford_base32_encode(&self.data))
    }
}

/// A 256bit ECDSA private key.
#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct EcdsaPrivateKey {
    data: [u8; 32],
}

impl EcdsaPrivateKey {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let data = <[u8; 32]>::try_from(b).ok()?;
        Some(Self { data })
    }

    /// Get the corresponding public key to this private key.
    pub fn get_public(&self) -> EcdsaPublicKey {
        use rcrypto::curve25519::ge_scalarmult_base;
        // the representation for scalarmult that rust-crypto expects is the reverse of libgcrypt
        // so we create temporary data and then reverse it
        // TODO cloning data every time this fn is called isn't ideal, consider reversing the representation in the struct
        let mut data = self.data;
        data.reverse();
        EcdsaPublicKey {
            data: ge_scalarmult_base(&data).to_bytes(),
        }
    }

    /// Return the private key of the global, anonymous user.
    pub fn anonymous() -> EcdsaPrivateKey {
        todo!()
    }

    pub fn zeros() -> EcdsaPrivateKey {
        EcdsaPrivateKey { data: [0u8; 32] }
    }
}

/*
impl FromStr for EcdsaPrivateKey {
    fn from_str(s: &str) -> Option<EcdsaPrivateKey> {
        let bytes = s.as_bytes();
        unsafe {
            let mut ret: EcdsaPrivateKey = mem::uninitialized();
            let res = ll::GNUNET_CRYPTO_ecdsa_private_key_from_string(
                bytes.as_ptr() as *const i8,
                bytes.len() as u64,
                &mut ret.data);
            match res {
                ll::GNUNET_OK => Some(ret),
                _             => None,
            }
        }
    }
}
*/

#[test]
fn test_ecdsa_to_from_string() {
    use EcdsaPublicKey;
    let s0: &str = "JK55QA8J1A164MB08VM209KE93M9JBB07M2VB8M3M03FKRFSV0MG";
    let key: EcdsaPublicKey = FromStr::from_str(s0).unwrap();
    let s1: String = format!("{}", key);
    println!("{} {}", s0, s0.len());
    println!("{} {}", s1, s1.len());
    assert!(s0 == &s1[..]);
}
