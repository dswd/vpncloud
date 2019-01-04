// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2017  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::ptr;
use std::ffi::CStr;
use std::sync::{Once, ONCE_INIT};
use ring::aead::*;

static CRYPTO_INIT: Once = ONCE_INIT;

use libc::{size_t, c_char, c_ulonglong, c_int};

use super::types::Error;

#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_ietf_KEYBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_ietf_NSECBYTES: usize = 0;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_ietf_NPUBBYTES: usize = 12;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_ietf_ABYTES: usize = 16;

#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_KEYBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_NSECBYTES: usize = 0;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_NPUBBYTES: usize = 12;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_ABYTES: usize = 16;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_STATEBYTES: usize = 512;

#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_STRBYTES: usize = 102;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: usize = 524_288;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: usize = 16_777_216;


#[link(name="sodium", kind="static")]
extern {
    pub fn sodium_init() -> c_int;
    pub fn randombytes_buf(buf: *mut u8, size: size_t);
    pub fn sodium_version_string() -> *const c_char;
    pub fn crypto_aead_aes256gcm_is_available() -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const [u8; crypto_pwhash_scryptsalsa208sha256_SALTBYTES],
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_ietf_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_beforenm(
        state: *mut [u8; crypto_aead_aes256gcm_STATEBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_encrypt_afternm(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_aes256gcm_NSECBYTES],
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        state: *const [u8; crypto_aead_aes256gcm_STATEBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_decrypt_afternm(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        state: *const [u8; crypto_aead_aes256gcm_STATEBYTES]) -> c_int;
}


#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CryptoMethod {
    #[serde(rename = "chacha20")]
    ChaCha20,
    #[serde(rename = "aes256")]
    AES256
}

pub struct CryptoData {
    sealing_key: SealingKey,
    opening_key: OpeningKey,
    nonce: Vec<u8>
}

pub enum Crypto {
    None,
    ChaCha20Poly1305(CryptoData),
    AES256GCM(CryptoData)
}

fn inc_nonce(nonce: &mut [u8]) {
    let l = nonce.len();
    for i in (0..l).rev() {
        let mut num = nonce[i];
        num = num.wrapping_add(1);
        nonce[i] = num;
        if num > 0 {
            break
        }
    }
}


impl Crypto {
    #[inline]
    pub fn init() {
        CRYPTO_INIT.call_once(|| {
            if unsafe { sodium_init() } != 0 {
                fail!("Failed to initialize crypto library");
            }
        });
    }

    #[inline]
    pub fn sodium_version() -> String {
        unsafe {
            CStr::from_ptr(sodium_version_string()).to_string_lossy().to_string()
        }
    }

    #[inline]
    pub fn aes256_available() -> bool {
        true
    }

    #[inline]
    pub fn method(&self) -> u8 {
        match *self {
            Crypto::None => 0,
            Crypto::ChaCha20Poly1305{..} => 1,
            Crypto::AES256GCM{..} => 2
        }
    }

    #[inline]
    pub fn nonce_bytes(&self) -> usize {
        match *self {
            Crypto::None => 0,
            Crypto::ChaCha20Poly1305(ref data) | Crypto::AES256GCM(ref data) => data.sealing_key.algorithm().nonce_len()
        }
    }

    #[inline]
    #[allow(unknown_lints,clippy::match_same_arms)]
    pub fn additional_bytes(&self) -> usize {
        match *self {
            Crypto::None => 0,
            Crypto::ChaCha20Poly1305{..} => crypto_aead_chacha20poly1305_ietf_ABYTES,
            Crypto::AES256GCM{..} => crypto_aead_aes256gcm_ABYTES
        }
    }

    pub fn from_shared_key(method: CryptoMethod, password: &str) -> Self {
        let salt = b"vpncloudVPNCLOUDvpncl0udVpnCloud";
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
            fail!("Key derivation failed");
        }
        let algo = match method {
            CryptoMethod::ChaCha20 => &CHACHA20_POLY1305,
            CryptoMethod::AES256 => &AES_256_GCM
        };
        let sealing_key = SealingKey::new(algo, &key[..algo.key_len()]).expect("Failed to create key");
        let opening_key = OpeningKey::new(algo, &key[..algo.key_len()]).expect("Failed to create key");
        let mut nonce: Vec<u8> = Vec::with_capacity(algo.nonce_len());
        for _ in 0..algo.nonce_len() {
            nonce.push(0);
        }
        unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
        let data = CryptoData { sealing_key, opening_key, nonce };
        match method {
            CryptoMethod::ChaCha20 => Crypto::ChaCha20Poly1305(data),
            CryptoMethod::AES256 => Crypto::AES256GCM(data)
        }
    }

    pub fn decrypt(&self, buf: &mut [u8], nonce: &[u8], header: &[u8]) -> Result<usize, Error> {
        match *self {
            Crypto::None => Ok(buf.len()),
            Crypto::ChaCha20Poly1305(ref data) | Crypto::AES256GCM(ref data) => {
                let plaintext = open_in_place(&data.opening_key, nonce, header, 0, buf).expect("error");
                Ok(plaintext.len())
            }
        }
    }

    pub fn encrypt(&mut self, buf: &mut [u8], mlen: usize, nonce_bytes: &mut [u8], header: &[u8]) -> usize {
        match *self {
            Crypto::None => mlen,
            Crypto::ChaCha20Poly1305(ref mut data) | Crypto::AES256GCM(ref mut data) => {
                inc_nonce(&mut data.nonce);
                let tag_len = data.sealing_key.algorithm().tag_len();
                assert!(buf.len() - mlen >= tag_len);
                let buf = &mut buf[.. mlen + tag_len];
                let new_len = seal_in_place(&data.sealing_key, &data.nonce, header, buf, tag_len).expect("error");
                unsafe {
                    ptr::copy_nonoverlapping(data.nonce.as_ptr(), nonce_bytes.as_mut_ptr(), data.nonce.len());
                }
                new_len
            }
        }
    }
}
