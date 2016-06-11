use std::mem::{size_of, uninitialized, size_of_val};
use std::fmt;
use std::str::{FromStr};
use std::io::{self, Read, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};

use gj::{Promise, WaitScope, EventPort};
use gjio::{Network};

use ll;
use Cfg;
use service::{self, connect, connect_async, ServiceReader, ServiceReader_Async, ReadMessageError, MessageTrait, MessageHeader};
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
pub fn iterate_peers(cfg: &Cfg) -> Result<Peers, IteratePeersError> {
    let (sr, mut sw) = try!(connect(cfg, "peerinfo"));

    let msg = ListAllPeersMessage::new(0);
    try!(sw.send(msg));
    Ok(Peers {
        service: sr,
    })
}

pub fn iterate_peers_async(cfg: &Cfg, network: &Network)
                           -> Promise<Peers_Async, IteratePeersError> {
    connect_async(cfg, "peerinfo", network)
        .lift()
        .then(move |(sr, mut sw)| {
            let msg = ListAllPeersMessage::new(0);
            sw.send(msg)
                .lift()
                .map(move |_| {
                Ok(Peers_Async {
                    service: sr,
                })
            })
        })
}

/// Get a peer by its key.
pub fn get_peer(cfg: &Cfg, pk_string: String) -> Result<(Option<PeerIdentity>, Option<Hello>), NextPeerError> {
    let mut peer = match list_peer_helper(cfg, pk_string) {
        Ok(p) => p,
        Err(_) => return Err(NextPeerError::InvalidResponse), // TODO need better error
    };
    match peer.next() {
        Some(Ok((id, hello))) => {
            match peer.next() {
                Some(_) => Err(NextPeerError::InvalidResponse), // cannot read two peers
                None => Ok((Some(id), hello)),
            }
        },
        Some(Err(e)) => Err(e),
        None => Ok((None, None)),
    }
}

fn list_peer_helper(cfg: &Cfg, pk_string: String) -> Result<Peers, IteratePeersError> {
    let (sr, mut sw) = try!(connect(cfg, "peerinfo"));

    let pk = & mut [0; 32];
    string_to_data(&pk_string, pk);

    let id =
        ll::Struct_GNUNET_PeerIdentity {
            public_key : ll::Struct_GNUNET_CRYPTO_EddsaPublicKey {
                q_y: *pk,
            }
        };
    let msg = ListPeerMessage::new(0, id);
    try!(sw.send(msg));
    Ok(Peers { service: sr })
}

pub fn self_id(cfg: &Cfg) -> Result<PeerIdentity, TransportServiceInitError> {
    let hello = try!(transport::self_hello(cfg));
    Ok(hello.id)
}

pub fn self_id_async(cfg: &Cfg, network: &Network) -> Promise<PeerIdentity, TransportServiceInitError> {
    transport::self_hello_async(cfg, network)
        .map(|hello| {
            Ok(hello.id)
        })
}

/// An iterator over all the currently connected peers.
pub struct Peers {
    service: ServiceReader,
}

pub struct Peers_Async {
    service: ServiceReader_Async,
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
        let (tpe, mr) = match self.service.read_message() {
            Err(e)  => return Some(Err(NextPeerError::ReadMessage { cause: e })),
            Ok(x)   => x,
        };
        read_peer(tpe, mr)
    }
}

impl Iterator for Peers_Async {
    type Item = Result<(PeerIdentity, Option<Hello>), NextPeerError>;

    fn next(&mut self) -> Option<Result<(PeerIdentity, Option<Hello>), NextPeerError>> {
        // TODO promises and iterators don't play nicely
        // we need to force the iterator to evaluate the promise on every iteration otherwise `next` will never return None
        // but keeping WaitScope and EventPort as a part of the Iterator isn't easy
        // see workaround in Peers_Async::next
        None
    }
}

impl Peers_Async {
    pub fn my_next(&mut self, wait_scope: & WaitScope, event_port: & mut EventPort<io::Error>) -> Option<Result<(PeerIdentity, Option<Hello>), NextPeerError>> {
        let (tpe, mr) = match self.service.read_message().wait(wait_scope, event_port) {
            Err(e)  => return Some(Err(NextPeerError::ReadMessage { cause: e })),
            Ok(x)   => x,
        };
        read_peer(tpe, mr)
    }
}


fn read_peer(tpe: u16, mut mr: Cursor<Vec<u8>>) -> Option<Result<(PeerIdentity, Option<Hello>), NextPeerError>> {
    match tpe {
        ll::GNUNET_MESSAGE_TYPE_PEERINFO_INFO => match mr.read_u32::<BigEndian>() {
            Err(e)  => match e.kind() {
                io::ErrorKind::UnexpectedEof => Some(Err(NextPeerError::Disconnected)),
                _                            => Some(Err(NextPeerError::Io { cause: e })),
            },
            Ok(x)   => match x == 0 {
                false => Some(Err(NextPeerError::InvalidResponse)),
                true  => match PeerIdentity::deserialize(&mut mr) {
                    Err(e)  => Some(Err(NextPeerError::Io { cause: e })),
                    Ok(pi)  => {
                        Some(Ok((pi, None)))
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
        ll::GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END => None,
        x => Some(Err(NextPeerError::UnexpectedMessageType { ty: x })),
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
