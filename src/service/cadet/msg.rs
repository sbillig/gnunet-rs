use crate::util::serial::*;
use crate::util::{MessageHeader, MessageType, PeerIdentity};
use std::convert::TryInto;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChannelId(pub u32);

pub struct ChannelOptions {
    pub no_buffer: bool,
    pub reliable: bool,
    pub out_of_order: bool,
}

impl ChannelOptions {
    /// Encode a `ChannelOptions` as a u32 for transmission across the network.
    pub fn as_u32(&self) -> u32 {
        let mut opt_code = 0;
        if self.no_buffer {
            opt_code |= 1
        };
        if self.reliable {
            opt_code |= 2
        };
        if self.out_of_order {
            opt_code |= 4
        };
        opt_code
    }
}

#[derive(AsBytes)]
#[repr(C)]
pub struct LocalChannelCreate {
    header: MessageHeader,
    id: u32be,
    peer_id: PeerIdentity,
    port: u32be,
    options: u32be,
}

impl LocalChannelCreate {
    pub fn new(id: ChannelId, peer_id: PeerIdentity, port: u32, options: ChannelOptions) -> Self {
        Self {
            header: MessageHeader::new(
                std::mem::size_of::<Self>().try_into().unwrap(),
                MessageType::CADET_LOCAL_CHANNEL_CREATE,
            ),
            id: u32be::new(id.0),
            peer_id,
            port: u32be::new(port),
            options: u32be::new(options.as_u32()),
        }
    }
}
