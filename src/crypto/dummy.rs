use super::super::types::Error;

pub enum Crypto {
    None
}

impl Crypto {
    pub fn method(&self) -> u8 {
        0
    }

    pub fn nonce_bytes(&self) -> usize {
        0
    }

    pub fn additional_bytes(&self) -> usize {
        0
    }

    pub fn from_shared_key(_password: &str) -> Self {
        panic!("This binary has no crypto support");
    }

    pub fn decrypt(&self, mut _buf: &mut [u8], _nonce: &[u8], _hash: &[u8]) -> Result<usize, Error> {
        unreachable!("This should never be called")
    }

    pub fn encrypt(&mut self, mut _buf: &mut [u8], _mlen: usize, _nonce_bytes: &mut [u8], _header: &[u8]) -> usize {
        unreachable!("This should never be called")
    }
}
