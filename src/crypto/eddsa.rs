use std::convert::TryFrom;
use zerocopy::{AsBytes, FromBytes};

#[repr(C)]
#[derive(Copy, Clone, AsBytes, FromBytes)]
pub struct EddsaPublicKey {
    pub q_y: [u8; 32],
}

impl EddsaPublicKey {
    pub fn bytes(&self) -> &[u8] {
        &self.q_y
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let q_y = <[u8; 32]>::try_from(b).ok()?;
        Some(Self { q_y })
    }
}

impl std::default::Default for EddsaPublicKey {
    fn default() -> Self {
        Self { q_y: [0; 32] }
    }
}
