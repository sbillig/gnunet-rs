use std::mem::{size_of, uninitialized, size_of_val};
use std::fmt;
use std::str::{FromStr};
use std::io::{self, Read, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};

use gj::{Promise, WaitScope};
use gjio::{Network, EventPort};

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

/// Get a peer by its key.
///
/// # Example
///
/// ```rust
/// use gnunet::Cfg;
/// use gnunet::util::async;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = async::EventPort::new().unwrap();
/// let network = event_port.get_network();
/// let pk_string = "DPQIBOOJV8QBS3FGJ6B0K5NTSQ9SULV45H5KCR4HU7PQ64N8Q9F0".to_string();
///
/// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let peer_promise = gnunet::get_peer(&config, &network, pk_string).map(|(peer, _)| { Ok(peer) });
///     let peer = peer_promise.wait(wait_scope, &mut event_port);
///     // do something with `peer`
///     Ok(())
/// }).expect("top_level");
/// ```
///
pub fn get_peer(cfg: &Cfg, network: &Network, pk_string: String) -> Promise<(Option<PeerIdentity>, Option<Hello>), NextPeerError> {
    // prepare peer identity
    let pk = &mut [0; 32];
    string_to_data(&pk_string, pk);
    let id =
        ll::Struct_GNUNET_PeerIdentity {
            public_key : ll::Struct_GNUNET_CRYPTO_EddsaPublicKey {
                q_y: *pk,
            }
        };

    // connect to the service
    connect(cfg, "peerinfo", network)
        .then(move |(sr, mut sw)| {
            sw.send(ListPeerMessage::new(0, id))
                .lift()
                .map(move |()| {
                    Ok(Peers { service: sr })
                })
        })
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

/// Get an proimise to all the currently connected peers.
///
/// # Example
///
/// ```rust
/// use gnunet::Cfg;
/// use gnunet::util::async;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = async::EventPort::new().unwrap();
/// let network = event_port.get_network();
///
/// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let peers_promise = gnunet::get_peers(&config, &network);
///     let peers = peers_promise.wait(wait_scope, &mut event_port);
///     // do things with `peers`, i.e. use its methods such as `to_iter` or `iterate`
///     Ok(())
/// }).expect("top_level");
/// ```
///
pub fn get_peers(cfg: &Cfg, network: &Network)
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

/// Get an iterator over all the currently connected peers.
///
/// # Example
///
/// ```rust
/// use gnunet::Cfg;
/// use gnunet::util::async;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = async::EventPort::new().unwrap();
/// let network = event_port.get_network();
///
/// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let peers_iter = gnunet::get_peers_iterator(&config, &network, wait_scope, &mut event_port).unwrap();
///     for peer in peers_iter {
///         let (peerinfo, _) = peer.unwrap();
///         // do something with `peerinfo`
///     }
///     Ok(())
/// }).expect("top_level");
/// ```
///
pub fn get_peers_iterator<'a>(cfg: &Cfg, network: &Network, wait_scope: &'a WaitScope, event_port: &'a mut EventPort)
                     -> Result<PeersIterator<'a>, IteratePeersError> {
    let peers = try!(get_peers(cfg, network).wait(wait_scope, event_port));
    Ok(peers.to_iter(wait_scope, event_port))
}

/// Get our own identity.
///
/// # Example
///
/// ```rust
/// use gnunet::Cfg;
/// use gnunet::util::async;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = async::EventPort::new().unwrap();
/// let network = event_port.get_network();
///
/// async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let get_self_id_promise = gnunet::get_self_id(&config, &network);
///     let get_self_id = get_self_id_promise.wait(wait_scope, &mut event_port);
///     // do something with `get_self_id`
///     Ok(())
/// }).expect("top_level");
/// ```
///
pub fn get_self_id(cfg: &Cfg, network: &Network) -> Promise<PeerIdentity, TransportServiceInitError> {
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

impl Peers {
    /// Returns a promise to the next iteration.
    pub fn iterate(&mut self) -> Promise<Option<(PeerIdentity, Option<Hello>)>, NextPeerError> {
        self.service.read_message()
            .map_else(move |x| {
                match x {
                    Err(e)  => return Err(NextPeerError::ReadMessage { cause: e }),
                    Ok((tpe, mr))   => parse_peer(tpe, mr),
                }
            })
    }

    /// Converts Peers into an Iterator.
    pub fn to_iter<'a>(self, wait_scope: &'a WaitScope, event_port: &'a mut EventPort) -> PeersIterator<'a> {
        PeersIterator {
            peers: self,
            event_port: event_port,
            wait_scope: wait_scope,
        }
    }
}

/// Parse some data in `mr` into a tuple of `PeerIdentity` and optionally a `Hello`.
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

/// Packed struct representing GNUNET_PEERINFO_ListAllPeersMessage.
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

/// Packed struct representing GNUNET_PEERINFO_ListPeerMessage.
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


// Promises and iterators don't play nicely with iterators
// We need to force the iterator to evaluate the promise on every iteration otherwise `next` will never return None
// But keeping WaitScope and EventPort as a part of the Iterator is tricky due to lifetime constraints
// So this struct is created as a workaround
pub struct PeersIterator<'a> {
    peers: Peers,
    wait_scope: &'a WaitScope,
    event_port: &'a mut EventPort,
}

impl <'a>Iterator for PeersIterator<'a> {
    type Item = Result<(PeerIdentity, Option<Hello>), NextPeerError>;

    fn next(&mut self) -> Option<Result<(PeerIdentity, Option<Hello>), NextPeerError>> {
        match self.peers.iterate().wait(self.wait_scope, self.event_port) {
            Ok(x) => match x {
                Some(x) => Some(Ok(x)),
                None    => None,
            },
            Err(e) => Some(Err(e)),
        }
    }
}
