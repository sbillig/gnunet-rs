use crate::util::{serial::*, time, MessageHeader, MessageIn, MessageType, PeerIdentity};

/// A `HelloMessage` that owns its buffers
pub type Hello = HelloMessage<String, Vec<u8>>;

/// A HELLO message is used to exchange information about
/// transports with other peers.
#[derive(Debug)]
pub struct HelloMessage<S, B> {
    prefix: HelloPrefix,
    pub addresses: Vec<HelloAddress<S, B>>,
}

impl<S, B> HelloMessage<S, B> {
    pub fn friend_only(&self) -> bool {
        self.prefix.friend_only_.get() != 0
    }

    pub fn peer_id(&self) -> &PeerIdentity {
        &self.prefix.id
    }
}

#[derive(Debug, Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct HelloPrefix {
    pub header: MessageHeader,
    friend_only_: u32be,
    pub id: PeerIdentity,
}

#[derive(Debug)]
pub struct HelloAddress<S, B> {
    pub transport_name: S,
    pub expiration: time::Absolute,
    /// Binary representation of the address (plugin-specific)
    pub address: B,
}

impl<'a, S, B> MessageIn<'a> for HelloMessage<S, B>
where
    S: From<&'a str>,
    B: From<&'a [u8]>,
{
    fn msg_type() -> MessageType {
        MessageType::HELLO
    }
    fn from_bytes(buf: &'a [u8]) -> Option<Self> {
        let (prefix, mut buf) = try_cast_prefix(buf)?;

        // prefix is followed some number of addresses, each composed of:
        // 1) transport-name (0-terminated)
        // 2) address-length (uint16_t, network byte order; possibly unaligned!)
        // 3) address expiration (`struct GNUNET_TIME_AbsoluteNBO`;
        //    possibly unaligned!)
        // 4) address (address-length buf; possibly unaligned!)

        let mut addresses = vec![];
        while !buf.is_empty() {
            let (transport_name, rest) = parse_leading_cstr(buf)?;
            let (addr_len, rest) = try_cast_prefix::<u16be>(rest)?;
            let (expiration, rest) = try_cast_prefix(rest)?;
            let (address, rest) = try_split_at(rest, addr_len.get() as usize)?;
            addresses.push(HelloAddress {
                transport_name: S::from(transport_name),
                expiration: *expiration,
                address: B::from(address),
            });
            buf = rest;
        }
        Some(HelloMessage {
            prefix: *prefix,
            addresses,
        })
    }
}
