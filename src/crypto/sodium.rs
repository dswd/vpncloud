use std::{mem, ptr};

use libsodium_sys::*;

use super::super::types::Error;

pub enum Crypto {
    None,
    ChaCha20Poly1305{key: [u8; 32], nonce: [u8; 8]}
}

fn inc_nonce(nonce: [u8; 8]) -> [u8; 8] {
    unsafe {
        let mut num: u64 = mem::transmute(nonce);
        num = num.wrapping_add(1);
        mem::transmute(num)
    }
}

impl Crypto {
    pub fn method(&self) -> u8 {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, nonce: _} => 1
        }
    }

    pub fn nonce_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, ref nonce} => nonce.len()
        }
    }

    pub fn additional_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, nonce: _} => crypto_aead_chacha20poly1305_ABYTES
        }
    }

    pub fn from_shared_key(password: &str) -> Self {
        let salt = "vpncloudVPNCLOUDvpncl0udVpnCloud".as_bytes();
        assert_eq!(salt.len(), crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
        let mut key = [0; crypto_pwhash_scryptsalsa208sha256_STRBYTES];
        let res = unsafe { crypto_pwhash_scryptsalsa208sha256(
            key.as_mut_ptr(),
            key.len() as u64,
            password.as_bytes().as_ptr(),
            password.as_bytes().len() as u64,
            salt.as_ptr() as *const [u8; crypto_pwhash_scryptsalsa208sha256_SALTBYTES],
            crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE as u64,
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
        ) };
        if res != 0 {
            panic!("Key derivation failed");
        }
        let mut crypto_key = [0; 32];
        for i in 0..crypto_key.len() {
            crypto_key[i] = key[i];
        }
        let mut nonce = [0u8; 8];
        unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
        Crypto::ChaCha20Poly1305{key: crypto_key, nonce: nonce}
    }

    pub fn decrypt(&self, mut buf: &mut [u8], nonce: &[u8], header: &[u8]) -> Result<usize, Error> {
        match self {
            &Crypto::None => Ok(buf.len()),
            &Crypto::ChaCha20Poly1305{ref key, nonce: _} => {
                let mut mlen: u64 = buf.len() as u64;
                let res = unsafe { crypto_aead_chacha20poly1305_decrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut mlen, // Mutable size of buffer (will be set to used size)
                    ptr::null_mut::<[u8; 0]>(), // Mutable base pointer to secret nonce (always NULL)
                    buf.as_ptr(), // Base pointer to message
                    buf.len() as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    nonce.as_ptr() as *const [u8; 8], // Base pointer to public nonce
                    key.as_ptr() as *const [u8; 32] // Base pointer to key
                ) };
                match res {
                    0 => Ok(mlen as usize),
                    _ => Err(Error::CryptoError("Failed to decrypt"))
                }
            }
        }
    }

    pub fn encrypt(&mut self, mut buf: &mut [u8], mlen: usize, nonce_bytes: &mut [u8], header: &[u8]) -> usize {
        match self {
            &mut Crypto::None => mlen,
            &mut Crypto::ChaCha20Poly1305{ref key, ref mut nonce} => {
                *nonce = inc_nonce(*nonce);
                let mut clen: u64 = buf.len() as u64;
                assert_eq!(nonce_bytes.len(), nonce.len());
                assert_eq!(nonce.len(), crypto_aead_chacha20poly1305_NPUBBYTES);
                assert_eq!(key.len(), crypto_aead_chacha20poly1305_KEYBYTES);
                assert_eq!(0, crypto_aead_chacha20poly1305_NSECBYTES);
                assert!(clen as usize >= mlen + crypto_aead_chacha20poly1305_ABYTES);
                let res = unsafe { crypto_aead_chacha20poly1305_encrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut clen, // Mutable size of buffer (will be set to used size)
                    buf.as_ptr(), // Base pointer to message
                    mlen as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    ptr::null::<[u8; 0]>(), // Base pointer to secret nonce (always NULL)
                    nonce.as_ptr() as *const [u8; 8], // Base pointer to public nonce
                    key.as_ptr() as *const [u8; 32] // Base pointer to key
                ) };
                assert_eq!(res, 0);
                assert_eq!(clen as usize, mlen + crypto_aead_chacha20poly1305_ABYTES);
                unsafe {
                    ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_bytes.as_mut_ptr(), nonce.len());
                }
                clen as usize
            }
        }
    }
}

#[test]
fn encrypt_decrypt() {
    let mut sender = Crypto::from_shared_key("test");
    let receiver = Crypto::from_shared_key("test");
    let msg = "HelloWorld0123456789";
    let msg_bytes = msg.as_bytes();
    let mut buffer = [0u8; 1024];
    let header = [0u8; 8];
    for i in 0..msg_bytes.len() {
        buffer[i] = msg_bytes[i];
    }
    let mut nonce1 = [0u8; 8];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce1, &header);
    assert_eq!(size, msg_bytes.len() + sender.additional_bytes());
    assert!(msg_bytes != &buffer[..msg_bytes.len()] as &[u8]);
    receiver.decrypt(&mut buffer[..size], &nonce1, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
    let mut nonce2 = [0u8; 8];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce2, &header);
    assert!(nonce1 != nonce2);
    receiver.decrypt(&mut buffer[..size], &nonce2, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
}
