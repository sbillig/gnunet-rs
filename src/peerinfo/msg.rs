use crate::crypto::PeerIdentity;
use crate::service::{MessageHeader, MessageTrait};
use crate::MessageType;
use std::convert::TryInto;
use std::mem::size_of;

/// Packed struct representing GNUNET_PEERINFO_ListAllPeersMessage.
#[repr(C, packed)]
pub struct ListAllPeers {
    header: MessageHeader,
    include_friend_only: u32,
}

impl ListAllPeers {
    pub fn new(include_friend_only: u32) -> ListAllPeers {
        let len = size_of::<ListAllPeers>();

        ListAllPeers {
            header: MessageHeader::new(len.try_into().unwrap(), MessageType::PEERINFO_GET_ALL),
            include_friend_only: include_friend_only.to_be(),
        }
    }
}

impl MessageTrait for ListAllPeers {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(ListAllPeers, self)
    }
}

/// Packed struct representing GNUNET_PEERINFO_ListPeerMessage.
#[repr(C, packed)]
pub struct ListPeer {
    header: MessageHeader,
    include_friend_only: u32,
    peer: PeerIdentity,
}

impl ListPeer {
    pub fn new(include_friend_only: u32, peer: PeerIdentity) -> ListPeer {
        let len = size_of::<ListPeer>();
        ListPeer {
            header: MessageHeader::new(len.try_into().unwrap(), MessageType::PEERINFO_GET),
            include_friend_only: include_friend_only.to_be(),
            peer,
        }
    }
}

impl MessageTrait for ListPeer {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(ListPeer, self)
    }
}
