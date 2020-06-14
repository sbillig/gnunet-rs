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
#[macro_use]
extern crate thiserror;
extern crate either;

pub mod crypto;
pub mod service;
pub mod util;
