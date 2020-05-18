use std::io::{self, Read};

pub trait ReadUtil: Read {
    fn read_exact_alloc(&mut self, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut ret = vec![0; len];
        self.read_exact(&mut ret[..])?;
        Ok(ret)
    }
}

impl<R> ReadUtil for R where R: Read {}
