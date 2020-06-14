use crate::util::serial::*;
use crate::util::{MessageHeader, MessageType, PeerIdentity};

#[derive(Debug, AsBytes)]
#[repr(C)]
pub struct Start {
    header: MessageHeader,
    options: u32be, // TODO: options enum?
    myself: PeerIdentity,
}

impl Start {
    pub fn new(options: u32, peer: PeerIdentity) -> Start {
        Self {
            header: MessageHeader::for_type::<Start>(MessageType::TRANSPORT_START),
            options: u32be::new(options),
            myself: peer,
        }
    }
}
