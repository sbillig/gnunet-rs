use std::mem::{uninitialized, size_of_val};
use std::fmt;
use std::str::{FromStr};
use std::io::{self, Read, Write};
use std::mem;
use std::slice;
use byteorder::{BigEndian, ReadBytesExt};

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
    let res = string_to_data(s.to_string(), pk);
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

  let msg = create_list_all_peers_message(0);
  let mw = sw.write_message2(msg);
  try!(mw.send());
  Ok(Peers {
    service: sr,
  })
}

pub fn self_id(cfg: &Cfg) -> Result<PeerIdentity, TransportServiceInitError> {
  let hello = try!(transport::self_hello(cfg));
  Ok(hello.id)
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
    let (tpe, mut mr) = match self.service.read_message() {
      Err(e)  => return Some(Err(NextPeerError::ReadMessage { cause: e })),
      Ok(x)   => x,
    };
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
struct ListAllPeerMessage {
    header: MessageHeader,
    include_friend_only: u32,
}

fn create_list_all_peers_message(include_friend_only: u32) -> ListAllPeerMessage {
    let len = mem::size_of::<ListAllPeerMessage>();
    use std::u16::MAX;
    assert!(len >= 4 && len <= (MAX as usize));

    ListAllPeerMessage {
        header: MessageHeader {
            len: (len as u16).to_be(),
            tpe: ll::GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL.to_be(),
        },
        include_friend_only: include_friend_only.to_be(),
    }
}

impl MessageTrait for ListAllPeerMessage {
    // TODO make this as macro?
    fn into_slice(&self) -> &[u8] {
        let p: *const ListAllPeerMessage = self;
        let p: *const u8 = p as *const u8;
        let res : &[u8] = unsafe {
            slice::from_raw_parts(p, mem::size_of::<ListAllPeerMessage>())
        };
        res
    }
}
