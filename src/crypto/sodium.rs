use std::mem;

use sodiumoxide::crypto::stream::chacha20::{Key as CryptoKey, Nonce, stream_xor_inplace, gen_nonce,
    KEYBYTES, NONCEBYTES};
use sodiumoxide::crypto::auth::hmacsha512256::{Key as AuthKey, Tag, authenticate, verify, TAGBYTES};
use sodiumoxide::crypto::pwhash::{derive_key, SALTBYTES, Salt, HASHEDPASSWORDBYTES,
    OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE};

use super::super::types::Error;

pub enum Crypto {
    None,
    ChaCha20HmacSha512256{crypto_key: CryptoKey, auth_key: AuthKey, nonce: Nonce}
}

fn inc_nonce(nonce: Nonce) -> Nonce {
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
            &Crypto::ChaCha20HmacSha512256{crypto_key: _, auth_key: _, nonce: _} => 1
        }
    }

    pub fn nonce_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20HmacSha512256{crypto_key: _, auth_key: _, nonce: _} => NONCEBYTES
        }
    }

    pub fn auth_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20HmacSha512256{crypto_key: _, auth_key: _, nonce: _} => TAGBYTES
        }
    }

    pub fn from_shared_key(password: &str) -> Self {
        let salt = "vpncloudVPNCLOUDvpncl0udVpnCloud";
        assert_eq!(salt.len(), SALTBYTES);
        let mut key = [0; HASHEDPASSWORDBYTES];
        derive_key(&mut key, password.as_bytes(), &Salt::from_slice(salt.as_bytes()).unwrap(),
            OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();
        let mut crypto_key = CryptoKey([0; KEYBYTES]);
        let mut auth_key = AuthKey([0; KEYBYTES]);
        for i in 0..KEYBYTES {
            crypto_key.0[i] = key[i];
        }
        for i in 0..KEYBYTES {
            auth_key.0[i] = key[KEYBYTES+i];
        }
        Crypto::ChaCha20HmacSha512256{crypto_key: crypto_key, auth_key: auth_key, nonce: gen_nonce()}
    }

    pub fn decrypt(&self, mut buf: &mut [u8], nonce: &[u8], hash: &[u8]) -> Result<(), Error> {
        match self {
            &Crypto::None => unreachable!("This should never be called"),
            &Crypto::ChaCha20HmacSha512256{ref crypto_key, ref auth_key, nonce: _} => {
                let nonce = Nonce::from_slice(nonce).unwrap();
                let hash = Tag::from_slice(hash).unwrap();
                stream_xor_inplace(&mut buf, &nonce, crypto_key);
                match verify(&hash, &buf, auth_key) {
                    true => Ok(()),
                    false => Err(Error::CryptoError("Decryption failed"))
                }
            }
        }
    }

    pub fn encrypt(&mut self, mut buf: &mut [u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            &mut Crypto::None => unreachable!("This should never be called"),
            &mut Crypto::ChaCha20HmacSha512256{ref crypto_key, ref auth_key, ref mut nonce} => {
                *nonce = inc_nonce(*nonce);
                let hash = authenticate(&buf, auth_key);
                stream_xor_inplace(&mut buf, nonce, crypto_key);
                (nonce.0.iter().map(|v| *v).collect(), hash.0.iter().map(|v| *v).collect())
            }
        }
    }
}

#[test]
fn encrypt_decrypt() {
    let mut sender = Crypto::from_shared_key("test");
    let receiver = Crypto::from_shared_key("test");
    let msg = "HelloWorld0123456789";
    let mut buffer: Vec<u8> = msg.bytes().collect();
    let (nonce1, hash1) = sender.encrypt(&mut buffer);
    assert!(msg.as_bytes() != &buffer as &[u8]);
    receiver.decrypt(&mut buffer, &nonce1, &hash1).unwrap();
    assert_eq!(msg.as_bytes(), &buffer as &[u8]);
    let (nonce2, hash2) = sender.encrypt(&mut buffer);
    assert!(nonce1 != nonce2);
    assert!(hash1 == hash2);
    receiver.decrypt(&mut buffer, &nonce2, &hash2).unwrap();
    assert_eq!(msg.as_bytes(), &buffer as &[u8]);
}
