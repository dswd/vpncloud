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

    pub fn auth_bytes(&self) -> usize {
        0
    }

    pub fn from_shared_key(_password: &str) -> Self {
        panic!("This binary has no crypto support");
    }

    pub fn decrypt(&self, mut _buf: &mut [u8], _nonce: &[u8], _hash: &[u8]) -> Result<(), Error> {
        unreachable!("This should never be called")
    }

    pub fn encrypt(&mut self, mut _buf: &mut [u8]) -> (Vec<u8>, Vec<u8>) {
        unreachable!("This should never be called")
    }
}
