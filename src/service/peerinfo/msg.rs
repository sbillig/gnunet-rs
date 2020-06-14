use crate::util::serial::*;
use crate::util::{Hello, MessageHeader, MessageIn, MessageType, PeerIdentity};
use std::convert::TryInto;
use std::mem::size_of;

#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct ListPeer {
    header: MessageHeader,
    include_friend_only: u32be,
    peer: PeerIdentity,
}

impl ListPeer {
    pub fn new(include_friend_only: bool, peer: PeerIdentity) -> ListPeer {
        let len = size_of::<ListPeer>();
        ListPeer {
            header: MessageHeader::new(len.try_into().unwrap(), MessageType::PEERINFO_GET),
            include_friend_only: U32::new(include_friend_only as u32),
            peer,
        }
    }
}

#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct ListAllPeers {
    header: MessageHeader,
    include_friend_only: u32be,
}

impl ListAllPeers {
    pub fn new(include_friend_only: bool) -> ListAllPeers {
        let len = size_of::<ListAllPeers>();

        ListAllPeers {
            header: MessageHeader::new(len.try_into().unwrap(), MessageType::PEERINFO_GET_ALL),
            include_friend_only: U32::new(include_friend_only as u32),
        }
    }
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct Notify {
    pub header: MessageHeader,
    pub include_friend_only: u32be,
}

pub struct Info {
    prefix: InfoPrefix,
    pub hello: Hello,
}

impl Info {
    pub fn into_id_and_hello(self) -> (PeerIdentity, Hello) {
        (self.prefix.peer_id, self.hello)
    }
}

impl MessageIn<'_> for Info {
    fn msg_type() -> MessageType {
        MessageType::PEERINFO_INFO
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        let (prefix, rest) = try_cast_prefix(b)?;
        dbg!(prefix);
        let hello = Hello::from_bytes(rest)?;
        Some(Info {
            prefix: *prefix,
            hello,
        })
    }
}

/// Followed by a Hello
#[derive(Copy, Clone, Debug, FromBytes)]
#[repr(C)]
pub struct InfoPrefix {
    header: MessageHeader,
    reserved: u32be,
    pub peer_id: PeerIdentity,
}

#[derive(Debug, Copy, Clone, FromBytes)]
#[repr(C)]
pub struct InfoEnd {
    pub header: MessageHeader,
}

impl MessageIn<'_> for InfoEnd {
    fn msg_type() -> MessageType {
        MessageType::PEERINFO_INFO_END
    }
    fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(*try_cast(b)?)
    }
}
