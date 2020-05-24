use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read, Write};
use std::str::from_utf8;
use std::str::FromStr;

use crate::crypto::hashcode::HashCode;
use crate::util::strings::{data_to_string, string_to_data};

/// A 256bit ECDSA public key.
#[derive(Copy, Clone)]
pub struct EcdsaPublicKey {
    data: [u8; 32],
}

impl EcdsaPublicKey {
    /// Serialize key to a byte stream.
    pub fn serialize<T>(&self, w: &mut T) -> Result<(), io::Error>
    where
        T: Write,
    {
        w.write_all(&self.data)
    }

    /// Compute the hash of this key.
    pub fn hash(&self) -> HashCode {
        HashCode::from_buffer(&self.data)
    }
}

/// Error generated when attempting to parse an ecdsa public key
#[derive(Debug, Error)]
pub enum EcdsaPublicKeyFromStrError {
    #[error("Failed to parse the string as an ecdsa public key")]
    ParsingFailed,
}

impl FromStr for EcdsaPublicKey {
    type Err = EcdsaPublicKeyFromStrError;

    fn from_str(s: &str) -> Result<EcdsaPublicKey, EcdsaPublicKeyFromStrError> {
        let mut res = [0; 32];
        if string_to_data(&s.to_string(), &mut res) {
            Ok(EcdsaPublicKey { data: res })
        } else {
            Err(EcdsaPublicKeyFromStrError::ParsingFailed)
        }
    }
}

impl Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let res = data_to_string(&self.data);
        fmt::Display::fmt(from_utf8(res.as_bytes()).unwrap(), f)
    }
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

/// A 256bit ECDSA private key.
#[derive(Copy, Clone)]
pub struct EcdsaPrivateKey {
    data: [u8; 32],
}

impl EcdsaPrivateKey {
    /// Serialize this key to a byte stream.
    pub fn serialize<T>(&self, w: &mut T) -> Result<(), io::Error>
    where
        T: Write,
    {
        w.write_all(&self.data)
    }

    /// Deserialize a from a byte stream.
    pub fn deserialize<T>(r: &mut T) -> Result<EcdsaPrivateKey, io::Error>
    where
        T: Read,
    {
        let mut sk = EcdsaPrivateKey { data: [0; 32] };
        r.read_exact(&mut sk.data[..])?;
        Ok(sk)
    }

    /// Deserialize a from a byte stream.
    pub fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<EcdsaPrivateKey, io::Error> {
        let mut data = [0; 32];
        data.copy_from_slice(b.as_ref());
        Ok(EcdsaPrivateKey { data })
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
