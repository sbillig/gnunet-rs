use crate::message_to_slice;
use crate::util::{MessageHeader, MessageTrait, MessageType, PeerIdentity};
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

#[allow(dead_code)]
pub struct LocalChannelCreate {
    header: MessageHeader,
    id: u32,
    peer_id: PeerIdentity,
    port: u32,
    options: u32,
}

impl LocalChannelCreate {
    pub fn new(id: ChannelId, peer_id: PeerIdentity, port: u32, options: ChannelOptions) -> Self {
        Self {
            header: MessageHeader::new(
                std::mem::size_of::<Self>().try_into().unwrap(),
                MessageType::CADET_LOCAL_CHANNEL_CREATE,
            ),
            id: id.0.to_be(),
            peer_id,
            port: port.to_be(),
            options: options.as_u32().to_be(),
        }
    }
}

impl MessageTrait for LocalChannelCreate {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(LocalChannelCreate, self)
    }
}
