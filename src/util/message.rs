use super::MessageType;
use crate::util::serial::*;
pub use either::*;
use smallvec::{smallvec, SmallVec};
use std::convert::TryInto;
use std::mem::size_of;

pub trait MessageIn<'a>: Sized {
    fn msg_type() -> MessageType;
    fn from_bytes(b: &'a [u8]) -> Option<Self>;
}

pub trait MessageOut {
    type Bytes: AsRef<[u8]>;
    fn as_bytes(&self) -> Self::Bytes;
}

impl<'a, T: AsBytes> MessageOut for &'a T {
    type Bytes = &'a [u8];
    fn as_bytes(&self) -> &'a [u8] {
        AsBytes::as_bytes(*self)
    }
}

pub trait MessageOutCompound {
    type Bytes: AsRef<[u8]>;
    type Chunks: IntoIterator<Item = Self::Bytes>;
    fn as_byte_chunks(&self) -> Self::Chunks;
}

impl<'a> MessageOutCompound for &'a FooMessage {
    type Bytes = &'a [u8];
    type Chunks = SmallVec<[&'a [u8]; 5]>;
    fn as_byte_chunks(&self) -> Self::Chunks {
        smallvec![
            self.prefix.as_bytes(),
            self.foo.as_bytes(),
            &[0u8][..],
            self.bar.as_bytes(),
            &[0u8][..],
        ]
    }
}

/// Error that can be generated when attempting to connect to a service.
#[derive(Debug, Error)]
pub enum ExpectError {
    #[error(
        "Unexpected message type: {msg_type} ({:?})",
        MessageType::from_u16(*msg_type)
    )]
    UnexpectedMessage { msg_type: u16 },

    #[error("Failed to parse message of type: {:?}", msg_type)]
    ParseFailure { msg_type: MessageType },
}

pub fn expect<'a, M: MessageIn<'a>>(msg_type: u16, bytes: &'a [u8]) -> Result<M, ExpectError> {
    if msg_type == M::msg_type().to_u16() {
        Ok(parse_msg(msg_type, bytes)?)
    } else {
        Err(ExpectError::UnexpectedMessage { msg_type })
    }
}

pub fn expect_either<'a, A: MessageIn<'a>, B: MessageIn<'a>>(
    msg_type: u16,
    bytes: &'a [u8],
) -> Result<Either<A, B>, ExpectError> {
    if msg_type == A::msg_type().to_u16() {
        Ok(Left(parse_msg::<A>(msg_type, bytes)?))
    } else if msg_type == B::msg_type().to_u16() {
        Ok(Right(parse_msg::<B>(msg_type, bytes)?))
    } else {
        Err(ExpectError::UnexpectedMessage { msg_type })
    }
}

fn parse_msg<'a, M: MessageIn<'a>>(msg_type: u16, b: &'a [u8]) -> Result<M, ExpectError> {
    assert!(msg_type == M::msg_type().to_u16());

    match M::from_bytes(b) {
        Some(m) => Ok(m),
        None => Err(ExpectError::ParseFailure {
            msg_type: M::msg_type(),
        }),
    }
}

#[derive(AsBytes)]
#[repr(C)]
pub struct FooPrefix {
    head: MessageHeader,
}
pub struct FooMessage {
    prefix: FooPrefix,
    foo: String,
    bar: String,
}

#[derive(Copy, Clone, Debug, PartialEq, AsBytes, FromBytes)]
#[repr(C)]
pub struct MessageHeader {
    len: u16be,
    typ: u16be,
}

impl MessageHeader {
    pub fn new(len: u16, msg_type: MessageType) -> Self {
        MessageHeader {
            len: u16be::new(len),
            typ: u16be::new(msg_type as u16),
        }
    }

    /// Panics if size_of::<T>() + size_of::<MessageHeader>() > 65,536
    pub fn for_type<T: Sized>(msg_type: MessageType) -> Self {
        let len = size_of::<MessageHeader>() + size_of::<T>();

        MessageHeader {
            len: u16be::new(len.try_into().unwrap()),
            typ: u16be::new(msg_type as u16),
        }
    }

    pub fn length(&self) -> u16 {
        self.len.get()
    }

    pub fn msg_type_u16(&self) -> u16 {
        self.typ.get()
    }

    pub fn msg_type(&self) -> Option<MessageType> {
        MessageType::from_u16(self.msg_type_u16())
    }
}

// pub trait MessageTrait {
//     fn into_slice(&self) -> &[u8];
// }

#[macro_export]
macro_rules! message_to_slice {
    ($t:ty, $i:ident) => {{
        use std::mem;
        use std::slice;
        let p: *const $t = $i;
        let p: *const u8 = p as *const u8;
        let res: &[u8] = unsafe { slice::from_raw_parts(p, mem::size_of::<$t>()) };
        res
    }};
}

#[test]
fn test_message_to_slice() {
    #[repr(C, packed)]
    struct S {
        a: u16,
        b: u32,
    }

    let s = &S { a: 0, b: 0 };
    let slice = message_to_slice!(S, s);

    assert!(slice.iter().all(|&x| x == 0));
    assert_eq!(slice.len(), 6);
}
