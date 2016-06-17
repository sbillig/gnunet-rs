use std::mem::{size_of, uninitialized, size_of_val};
use std::fmt;
use std::str::{FromStr};
use std::io::{self, Read, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};

use gj::{Promise};
use gjio::{Network};

use ll;
use Cfg;
use service::{self, connect, ServiceReader, ReadMessageError, MessageTrait, MessageHeader};
use Hello;
use transport::{self, TransportServiceInitError};
use util::strings::{data_to_string, string_to_data};

/// The identity of a GNUnet peer.
pub struct PeerIdentity {
    data: ll::Struct_GNUNET_PeerIdentity,
}

impl PeerIdentity {
    pub fn deserialize<R>(r: &mut R) -> Result<PeerIdentity, io::Error> where R: Read {
        let mut ret: PeerIdentity = unsafe { uninitialized() };
        try!(r.read_exact(&mut ret.data.public_key.q_y[..]));
        Ok(ret)
    }

    pub fn serialize<T>(&self, w: &mut T) -> Result<(), io::Error> where T: Write {
        w.write_all(&self.data.public_key.q_y[..])
    }
}

/// Error generated when attempting to parse a PeerIdentity
error_def! PeerIdentityFromStrError {
    ParsingFailed => "Failed to parse the string as a PeerIdentity"
}

impl FromStr for PeerIdentity {
    type Err = PeerIdentityFromStrError;

    fn from_str(s: &str) -> Result<PeerIdentity, PeerIdentityFromStrError> {
        let pk = &mut [0; 32]; // TODO can we dynamically set the size?
        let res = string_to_data(&s.to_string(), pk);
        match res {
            true => Ok(PeerIdentity {
                data: ll::Struct_GNUNET_PeerIdentity {
                    public_key: ll::Struct_GNUNET_CRYPTO_EddsaPublicKey {
                        q_y: *pk,
                    }
                }
            }),
            _ => Err(PeerIdentityFromStrError::ParsingFailed),
        }
    }
}

/// Errors returned by `iterate_peers`.
error_def! IteratePeersError {
    Io { #[from] cause: io::Error }
        => "There as an I/O error communicating with the peerinfo service" ("Specifically: {}", cause),
    Connect { #[from] cause: service::ConnectError }
        => "Failed to connect to the peerinfo service" ("Reason: {}", cause)
}

/// Iterate over all the currently connected peers.
pub fn iterate_peers(cfg: &Cfg, network: &Network)
                           -> Promise<Peers, IteratePeersError> {
    connect(cfg, "peerinfo", network)
        .lift()
        .then(move |(sr, mut sw)| {
            sw.send(ListAllPeersMessage::new(0))
                .lift()
                .map(move |()| {
                    Ok(Peers { service: sr })
                })
        })
}

/// Get a peer by its key.
pub fn get_peer(cfg: &Cfg, network: &Network, pk_string: String) -> Promise<(Option<PeerIdentity>, Option<Hello>), NextPeerError> {
    get_peer_helper(cfg, network, pk_string)
        .map_err(|_| { NextPeerError::InvalidResponse }) // TODO need better error handling
        .then(move |mut peer| {
            peer.iterate()
                .map(|x| {
                    match x {
                        Some((id, hello)) => Ok((Some(id), hello)),
                        None => Ok((None, None)),
                    }
                })
                .then(move |x| {
                    peer.iterate()
                        .map(|y| {
                            match y {
                                Some(_) => Err(NextPeerError::InvalidResponse), // wrong if we manage to read two peers
                                None => Ok(x),
                            }
                        })
                })
        })
}

fn get_peer_helper(cfg: &Cfg, network: &Network, pk_string: String) -> Promise<Peers, IteratePeersError> {
    let pk = & mut [0; 32];
    string_to_data(&pk_string, pk);
    let id =
        ll::Struct_GNUNET_PeerIdentity {
            public_key : ll::Struct_GNUNET_CRYPTO_EddsaPublicKey {
                q_y: *pk,
            }
        };

    connect(cfg, "peerinfo", network)
        .lift()
        .then(move |(sr, mut sw)| {
            sw.send(ListPeerMessage::new(0, id))
                .lift()
                .map(move |()| {
                    Ok(Peers { service: sr })
                })
        })
}

pub fn self_id(cfg: &Cfg, network: &Network) -> Promise<PeerIdentity, TransportServiceInitError> {
    transport::self_hello(cfg, network)
        .map(|hello| {
            Ok(hello.id)
        })
}

/// An iterator over all the currently connected peers.
pub struct Peers {
    service: ServiceReader,
}

/// Errors returned by `Peers::next`.
error_def! NextPeerError {
    InvalidResponse
        => "The response from the gnunet-peerinfo service was incoherent",
    UnexpectedMessageType { ty: u16 }
        => "The peerinfo service sent an unexpected response message type" ("Message type {} was not expected", ty),
    Io { #[from] cause: io::Error }
        => "There was an I/O error communicating with the peerinfo service" ("Specifically: {}", cause),
    ReadMessage { #[from] cause: ReadMessageError }
        => "Failed to receive the response from the peerinfo service" ("Reason: {}", cause),
    Disconnected
        => "The service disconnected unexpectedly"
}

impl Iterator for Peers {
    type Item = Result<(PeerIdentity, Option<Hello>), NextPeerError>;

    fn next(&mut self) -> Option<Result<(PeerIdentity, Option<Hello>), NextPeerError>> {
        // promises and iterators don't play nicely
        // we need to force the iterator to evaluate the promise on every iteration otherwise `next` will never return None
        // but keeping WaitScope and EventPort as a part of the Iterator isn't easy
        // see workaround in Peers::iterate
        unimplemented!()
    }
}

impl Peers {
    pub fn iterate(&mut self) -> Promise<Option<(PeerIdentity, Option<Hello>)>, NextPeerError> {
        self.service.read_message()
            .map_else(move |x| {
                match x {
                    Err(e)  => return Err(NextPeerError::ReadMessage { cause: e }),
                    Ok((tpe, mr))   => parse_peer(tpe, mr),
                }
            })
    }
}

fn parse_peer(tpe: u16, mut mr: Cursor<Vec<u8>>) -> Result<Option<(PeerIdentity, Option<Hello>)>, NextPeerError> {
    match tpe {
        ll::GNUNET_MESSAGE_TYPE_PEERINFO_INFO => match mr.read_u32::<BigEndian>() {
            Err(e)  => match e.kind() {
                io::ErrorKind::UnexpectedEof => Err(NextPeerError::Disconnected),
                _                            => Err(NextPeerError::Io { cause: e }),
            },
            Ok(x)   => match x == 0 {
                false => Err(NextPeerError::InvalidResponse),
                true  => match PeerIdentity::deserialize(&mut mr) {
                    Err(e)  => Err(NextPeerError::Io { cause: e }),
                    Ok(pi)  => {
                        Ok(Some((pi, None)))
                        /*
                            * when we have hello parsing
                            match mr.eof() {
                            true  => Some(Ok(pi, None)),
                            false => {

                    },
                    }
                            */
                    },
                },
            },
        },
        ll::GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END => Ok(None),
        x => Err(NextPeerError::UnexpectedMessageType { ty: x }),
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        assert!(52usize == (size_of_val(&self.data.public_key.q_y) * 8 + 4) / 5);
        let res = data_to_string(&self.data.public_key.q_y);
        fmt::Display::fmt(res.as_str(), f)
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[repr(C, packed)]
struct ListAllPeersMessage {
    header: MessageHeader,
    include_friend_only: u32,
}

impl ListAllPeersMessage {
    fn new(include_friend_only: u32) -> ListAllPeersMessage {
        let len = size_of::<ListAllPeersMessage>();
        use std::u16::MAX;
        assert!(len >= 4 && len <= (MAX as usize));

        ListAllPeersMessage {
            header: MessageHeader {
                len: (len as u16).to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL.to_be(),
            },
            include_friend_only: include_friend_only.to_be(),
        }
    }
}


impl MessageTrait for ListAllPeersMessage {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(ListAllPeersMessage, self)
    }
}

#[repr(C, packed)]
struct ListPeerMessage {
    header: MessageHeader,
    include_friend_only: u32,
    peer: ll::Struct_GNUNET_PeerIdentity,
}

impl ListPeerMessage {
    fn new(include_friend_only: u32, peer: ll::Struct_GNUNET_PeerIdentity) -> ListPeerMessage {
        let len = size_of::<ListPeerMessage>();
        ListPeerMessage {
            header: MessageHeader {
                len: (len as u16).to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_PEERINFO_GET.to_be(),
            },
            include_friend_only: include_friend_only.to_be(),
            peer: peer,
        }
    }
}

impl MessageTrait for ListPeerMessage {
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(ListPeerMessage, self)
    }
}

    /*
#[repr(C, packed)]
struct InfoMessage {
    header: MessageHeader,
    reserved: u32,
    peer: ll::Struct_GNUNET_PeerIdentity,
}
    */
