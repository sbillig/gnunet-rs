use super::MessageType;

#[repr(C, packed)]
pub struct MessageHeader {
    len: u16, // bigendian
    typ: u16, // bigendian
}

impl MessageHeader {
    pub fn new(len: u16, msg_type: MessageType) -> Self {
        MessageHeader {
            len: len.to_be(),
            typ: (msg_type as u16).to_be(),
        }
    }

    pub fn length(&self) -> u16 {
        self.len.to_le()
    }

    pub fn msg_type_u16(&self) -> u16 {
        self.typ.to_le()
    }

    pub fn msg_type(&self) -> Option<MessageType> {
        MessageType::from_u16(self.msg_type_u16())
    }
}

pub trait MessageTrait {
    fn into_slice(&self) -> &[u8];
}

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
