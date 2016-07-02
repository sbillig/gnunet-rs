use std::io::{Error, ErrorKind};
use gj::{Promise};
use gjio::{AsyncRead, SocketStream};
use byteorder::{BigEndian, ByteOrder};

pub fn cancel<T, E: From<Error>>(p: Promise<T, E>) -> Promise<T, E> {
    let err = Promise::err(Error::new(ErrorKind::Interrupted, "Promise cancelled"));
    err.lift().eagerly_evaluate().exclusive_join(p)
}


// TODO better if this is a part of gjio
pub fn read_u16_from_socket(socket: & mut SocketStream) -> Promise<u16, Error>{
    socket.read(vec![0;2], 2).then(move |(buf, len)| {
        assert!(len == 2);
        Promise::ok(BigEndian::read_u16(&buf[..]))
    })
}
