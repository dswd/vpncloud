use sodiumoxide::crypto::stream::chacha20::{Key as CryptoKey, Nonce, stream_xor_inplace, gen_nonce,
    KEYBYTES};
use sodiumoxide::crypto::auth::hmacsha512256::{Key as AuthKey, Tag, authenticate, verify};
use sodiumoxide::crypto::pwhash::{derive_key, SALTBYTES, Salt, HASHEDPASSWORDBYTES,
    OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE};

use super::types::Error;

pub enum Crypto {
    None,
    ChaCha20HmacSha512256{key: Vec<u8>, nonce: Vec<u8>}
}

fn inc_nonce(nonce: &mut [u8]) {
    let len = nonce.len();
    for i in 1..len+1 {
        let mut val = nonce[len-i];
        val = val.wrapping_add(1);
        nonce[len-i] = val;
        if val != 0 {
            break;
        }
    }
}

impl Crypto {
    pub fn is_secure(&self) -> bool {
        match self {
            &Crypto::None => false,
            _ => true
        }
    }

    pub fn from_shared_key(password: &str) -> Self {
        let salt = "vpncloudVPNCLOUDvpncl0udVpnCloud";
        assert_eq!(salt.len(), SALTBYTES);
        let mut key = [0; HASHEDPASSWORDBYTES];
        derive_key(&mut key, password.as_bytes(), &Salt::from_slice(salt.as_bytes()).unwrap(),
            OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE).unwrap();
        let key = key[..KEYBYTES].iter().map(|b| *b).collect();
        let nonce = gen_nonce().0.iter().map(|b| *b).collect();
        Crypto::ChaCha20HmacSha512256{key: key, nonce: nonce}
    }

    pub fn decrypt(&self, mut buf: &mut [u8], nonce: &[u8], hash: &[u8]) -> Result<(), Error> {
        match self {
            &Crypto::None => Ok(()),
            &Crypto::ChaCha20HmacSha512256{ref key, nonce: _} => {
                let crypto_key = CryptoKey::from_slice(key).unwrap();
                let nonce = Nonce::from_slice(nonce).unwrap();
                let auth_key = AuthKey::from_slice(key).unwrap();
                let hash = Tag::from_slice(hash).unwrap();
                stream_xor_inplace(&mut buf, &nonce, &crypto_key);
                match verify(&hash, &buf, &auth_key) {
                    true => Ok(()),
                    false => Err(Error::CryptoError("Decryption failed"))
                }
            }
        }
    }

    pub fn encrypt(&mut self, mut buf: &mut [u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            &mut Crypto::None => (Vec::new(), Vec::new()),
            &mut Crypto::ChaCha20HmacSha512256{ref key, ref mut nonce} => {
                let crypto_key = CryptoKey::from_slice(key).unwrap();
                let auth_key = AuthKey::from_slice(key).unwrap();
                inc_nonce(nonce);
                let hash = authenticate(&buf, &auth_key);
                stream_xor_inplace(&mut buf, &Nonce::from_slice(&nonce).unwrap(), &crypto_key);
                (nonce.clone(), hash.0.iter().map(|v| *v).collect())
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
