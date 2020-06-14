use crate::crypto::EcdsaPrivateKey;
use crate::util::serial::*;
use crate::util::{MessageHeader, MessageIn, MessageOutCompound, MessageType};
use num::ToPrimitive;
use smallvec::{smallvec, SmallVec};

#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct Lookup {
    header: MessageHeader,
}

impl Lookup {
    pub fn new() -> Self {
        Self {
            header: MessageHeader::new(4, MessageType::IDENTITY_START),
        }
    }
}

/// Followed by `name_len` bytes (null-terminated string).
#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct GetDefaultPrefix {
    header: MessageHeader,
    name_len: u16be,
    reserved: u16be, // always zero
}

pub struct GetDefault<S> {
    prefix: GetDefaultPrefix,
    name: S,
}

impl<S> GetDefault<S>
where
    S: AsRef<str>,
{
    pub fn new(name: S) -> Option<Self> {
        let name_len = name.as_ref().len() + 1; // trailing null
        if let Some(msg_len) = (std::mem::size_of::<GetDefaultPrefix>() + name_len).to_u16() {
            Some(Self {
                prefix: GetDefaultPrefix {
                    header: MessageHeader::new(msg_len, MessageType::IDENTITY_GET_DEFAULT),
                    name_len: U16::new(name_len as u16),
                    reserved: U16::ZERO,
                },
                name,
            })
        } else {
            None
        }
    }
}

impl<'a, S> MessageOutCompound for &'a GetDefault<S>
where
    S: AsRef<str>,
{
    type Bytes = &'a [u8];
    type Chunks = SmallVec<[&'a [u8]; 3]>;

    fn as_byte_chunks(&self) -> Self::Chunks {
        smallvec![
            self.prefix.as_bytes(),
            self.name.as_ref().as_bytes(),
            &[0][..]
        ]
    }
}

/// Followed by `name_len` bytes (null-terminated string).
#[derive(Copy, Clone, FromBytes)]
#[repr(C)]
pub struct SetDefaultPrefix {
    pub header: MessageHeader,
    pub name_len: u16be,
    pub reserved: u16be,
    pub private_key: EcdsaPrivateKey,
}

pub struct SetDefault<S> {
    pub prefix: SetDefaultPrefix,
    name: S,
}

impl<S> SetDefault<S> {
    pub fn into_name_and_key(self) -> (S, EcdsaPrivateKey) {
        (self.name, self.prefix.private_key)
    }
}

impl<'a, S> MessageIn<'a> for SetDefault<S>
where
    S: From<&'a str>,
{
    fn msg_type() -> MessageType {
        MessageType::IDENTITY_SET_DEFAULT
    }
    fn from_bytes(b: &'a [u8]) -> Option<Self> {
        let (prefix, name) = try_parse_prefix_and_str(b)?;
        Some(Self {
            prefix: *prefix,
            name: S::from(name),
        })
    }
}

#[derive(FromBytes)]
#[repr(C)]
pub struct Update {
    pub header: MessageHeader,
    pub name_len: u16be,
    pub end_of_list: u16be,
    pub private_key: EcdsaPrivateKey,
}

impl Update {
    pub fn end_of_list(&self) -> bool {
        self.end_of_list.get() != 0
    }
}

#[derive(Copy, Clone, FromBytes)]
#[repr(C)]
pub struct ResultCodePrefix {
    pub header: MessageHeader,
    pub result_code: u32be,
}

pub struct ResultCode<S> {
    pub prefix: ResultCodePrefix,
    pub err_msg: S,
}

impl<'a, S> MessageIn<'a> for ResultCode<S>
where
    S: From<&'a str>,
{
    fn msg_type() -> MessageType {
        MessageType::IDENTITY_RESULT_CODE
    }

    fn from_bytes(b: &'a [u8]) -> Option<Self> {
        let (prefix, err_msg) = try_parse_prefix_and_str(b)?;
        Some(Self {
            prefix: *prefix,
            err_msg: S::from(err_msg),
        })
    }
}

#[derive(FromBytes)]
#[repr(C)]
pub struct CreateRequest {
    pub header: MessageHeader,
    pub name_len: u16be,
    pub reserved: u16be,
    pub private_key: EcdsaPrivateKey,
}

#[derive(FromBytes)]
#[repr(C)]
pub struct Rename {
    pub header: MessageHeader,
    pub old_name_len: u16be,
    pub new_name_len: u16be,
}

#[derive(FromBytes)]
#[repr(C)]
pub struct Delete {
    pub header: MessageHeader,
    pub name_len: u16be,
    pub reserved: u16be,
}
