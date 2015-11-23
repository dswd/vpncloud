use super::types::Error;

pub enum Crypto {
    None
}

impl Crypto {
    pub fn is_secure(&self) -> bool {
        false
    }

    pub fn from_shared_key(_password: &str) -> Self {
        panic!("This binary has no crypto support");
    }

    pub fn decrypt(&self, mut _buf: &mut [u8], _nonce: &[u8], _hash: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    pub fn encrypt(&mut self, mut _buf: &mut [u8]) -> (Vec<u8>, Vec<u8>) {
        (Vec::new(), Vec::new())
    }
}
