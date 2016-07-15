use std::io::{Error, ErrorKind};
use gj::{Promise};
use gjio::{AsyncRead, SocketStream};
use byteorder::{BigEndian, ByteOrder};

pub fn cancel<T, E: From<Error>>(p: Promise<T, E>) -> Promise<T, E> {
    let err = Promise::err(Error::new(ErrorKind::Interrupted, "Promise cancelled"));
    err.lift().eagerly_evaluate().exclusive_join(p)
}

impl U16PromiseReader for SocketStream {
    fn read_u16(&mut self) -> Promise<u16, Error> {
        self.read(vec![0;2], 2).map(move |(buf, len)| {
            assert!(len == 2);
            Ok(BigEndian::read_u16(&buf[..]))
        })
    }
}

pub trait U16PromiseReader {
    fn read_u16(&mut self) -> Promise<u16, Error>;
}
