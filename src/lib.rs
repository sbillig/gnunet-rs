//! # Rust interface for GNUnet. GNU's framework for secure peer-to-peer networking.
//!
//! This library does not implement a GNUnet peer. You must have the GNUnet software installed and
//! running in order to use this library.
//! ```

#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate crypto as rcrypto;
extern crate libc;
extern crate num;
#[macro_use]
extern crate num_derive;
extern crate rand;
extern crate regex;
extern crate unix_socket;
#[macro_use]
extern crate gj;
extern crate gjio;
#[macro_use]
extern crate thiserror;

pub use crate::crypto::{EcdsaPrivateKey, EcdsaPublicKey, HashCode};
pub use configuration::Cfg;

pub use gns::{lookup_in_master, LocalOptions, GNS};
pub use hello::Hello;
pub use identity::{get_default_ego, Ego, IdentityService};
mod message_type;
pub use message_type::MessageType;
pub use peerinfo::{get_peer, get_peers, get_peers_vec, get_self_id, PeerIdentity};
//pub use dht::DHT;

mod ll;

#[macro_use]
pub mod service;
pub mod configuration;
pub mod gns;
pub mod paths;
pub mod time;
//pub mod dht;
mod crypto;
pub mod hello;
pub mod identity;
pub mod peerinfo;
pub mod util;
//pub mod cadet;
pub mod data;
pub mod transport;
