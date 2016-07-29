use std::io::{Error, ErrorKind};
use gj::{self, Promise};
use gjio::{self, AsyncRead, SocketStream};
use byteorder::{BigEndian, ByteOrder};

pub type EventLoop = gj::EventLoop;

pub type EventPort = gjio::EventPort;

pub fn cancel<T, E: From<Error>>(p: Promise<T, E>) -> Promise<T, E> {
    let err = Promise::err(Error::new(ErrorKind::Interrupted, "Promise cancelled"));
    err.lift().eagerly_evaluate().exclusive_join(p)
}

impl PromiseReader for SocketStream {
    fn read_u16(&mut self) -> Promise<u16, Error> {
        self.read(vec![0;2], 2).map(move |(buf, len)| {
            assert!(len == 2);
            Ok(BigEndian::read_u16(&buf[..]))
        })
    }

    fn read_u32(&mut self) -> Promise<u32, Error> {
        self.read(vec![0;4], 4).map(move |(buf, len)| {
            assert!(len == 4);
            Ok(BigEndian::read_u32(&buf[..]))
        })
    }
}

pub trait PromiseReader {
    fn read_u16(&mut self) -> Promise<u16, Error>;
    fn read_u32(&mut self) -> Promise<u32, Error>;
}
