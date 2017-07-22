// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::ptr;
use std::ffi::CStr;
use std::sync::{Once, ONCE_INIT};

static CRYPTO_INIT: Once = ONCE_INIT;

use libc::{size_t, c_char, c_ulonglong, c_int};
use aligned_alloc::{aligned_alloc, aligned_free};

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
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: usize = 524288;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: usize = 16777216;

pub struct Aes256State(*mut [u8; crypto_aead_aes256gcm_STATEBYTES]);

impl Aes256State {
    fn new() -> Aes256State {
        let ptr = aligned_alloc(crypto_aead_aes256gcm_STATEBYTES, 16)
            as *mut [u8; crypto_aead_aes256gcm_STATEBYTES];
        Aes256State(ptr)
    }
}

impl Drop for Aes256State {
    fn drop(&mut self) {
        unsafe { aligned_free(self.0 as *mut ()) }
    }
}


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

pub enum Crypto {
    None,
    ChaCha20Poly1305{
        key: [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES],
        nonce: [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES]
    },
    AES256GCM{
        state: Aes256State,
        nonce: [u8; crypto_aead_aes256gcm_NPUBBYTES]
    }
}

fn inc_nonce_12(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        let mut num = nonce[11-i];
        num = num.wrapping_add(1);
        nonce[11-i] = num;
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
        unsafe {
            crypto_aead_aes256gcm_is_available() == 1
        }
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
            Crypto::ChaCha20Poly1305{ref nonce, ..} | Crypto::AES256GCM{ref nonce, ..} => nonce.len(),
        }
    }

    #[inline]
    #[allow(unknown_lints)]
    #[allow(match_same_arms)]
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
        match method {
            CryptoMethod::ChaCha20 => {
                let mut crypto_key = [0; crypto_aead_chacha20poly1305_ietf_KEYBYTES];
                crypto_key.clone_from_slice(&key[..crypto_aead_chacha20poly1305_ietf_KEYBYTES]);
                let mut nonce = [0u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
                unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
                Crypto::ChaCha20Poly1305{key: crypto_key, nonce: nonce}
            },
            CryptoMethod::AES256 => {
                if ! Crypto::aes256_available() {
                    fail!("AES256 is not supported by this processor, use ChaCha20 instead");
                }
                let mut nonce = [0u8; crypto_aead_aes256gcm_NPUBBYTES];
                unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
                let state = Aes256State::new();
                let res = unsafe { crypto_aead_aes256gcm_beforenm(
                    state.0,
                    key[..crypto_aead_aes256gcm_KEYBYTES].as_ptr() as *const [u8; crypto_aead_aes256gcm_KEYBYTES]
                ) };
                assert_eq!(res, 0);
                Crypto::AES256GCM{state: state, nonce: nonce}
            }
        }
    }

    pub fn decrypt(&self, mut buf: &mut [u8], nonce: &[u8], header: &[u8]) -> Result<usize, Error> {
        match *self {
            Crypto::None => Ok(buf.len()),
            Crypto::ChaCha20Poly1305{ref key, ..} => {
                let mut mlen: u64 = buf.len() as u64;
                let res = unsafe { crypto_aead_chacha20poly1305_ietf_decrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut mlen, // Mutable size of buffer (will be set to used size)
                    ptr::null_mut::<[u8; 0]>(), // Mutable base pointer to secret nonce (always NULL)
                    buf.as_ptr(), // Base pointer to message
                    buf.len() as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    nonce.as_ptr() as *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES], // Base pointer to public nonce
                    key.as_ptr() as *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES] // Base pointer to key
                ) };
                match res {
                    0 => Ok(mlen as usize),
                    _ => Err(Error::Crypto("Failed to decrypt"))
                }
            },
            Crypto::AES256GCM{ref state, ..} => {
                let mut mlen: u64 = buf.len() as u64;
                let res = unsafe { crypto_aead_aes256gcm_decrypt_afternm(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut mlen, // Mutable size of buffer (will be set to used size)
                    ptr::null_mut::<[u8; 0]>(), // Mutable base pointer to secret nonce (always NULL)
                    buf.as_ptr(), // Base pointer to message
                    buf.len() as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    nonce.as_ptr() as *const [u8; crypto_aead_aes256gcm_NPUBBYTES], // Base pointer to public nonce
                    state.0 // Base pointer to state
                ) };
                match res {
                    0 => Ok(mlen as usize),
                    _ => Err(Error::Crypto("Failed to decrypt"))
                }
            }
        }
    }

    pub fn encrypt(&mut self, mut buf: &mut [u8], mlen: usize, nonce_bytes: &mut [u8], header: &[u8]) -> usize {
        match *self {
            Crypto::None => mlen,
            Crypto::ChaCha20Poly1305{ref key, ref mut nonce} => {
                inc_nonce_12(nonce);
                let mut clen: u64 = buf.len() as u64;
                assert_eq!(nonce_bytes.len(), nonce.len());
                assert!(clen as usize >= mlen + crypto_aead_chacha20poly1305_ietf_ABYTES);
                let res = unsafe { crypto_aead_chacha20poly1305_ietf_encrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut clen, // Mutable size of buffer (will be set to used size)
                    buf.as_ptr(), // Base pointer to message
                    mlen as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    ptr::null::<[u8; 0]>(), // Base pointer to secret nonce (always NULL)
                    nonce.as_ptr() as *const [u8; crypto_aead_chacha20poly1305_ietf_NPUBBYTES], // Base pointer to public nonce
                    key.as_ptr() as *const [u8; crypto_aead_chacha20poly1305_ietf_KEYBYTES] // Base pointer to key
                ) };
                assert_eq!(res, 0);
                unsafe {
                    ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_bytes.as_mut_ptr(), nonce.len());
                }
                clen as usize
            },
            Crypto::AES256GCM{ref state, ref mut nonce} => {
                inc_nonce_12(nonce);
                let mut clen: u64 = buf.len() as u64;
                assert_eq!(nonce_bytes.len(), nonce.len());
                assert!(clen as usize >= mlen + crypto_aead_aes256gcm_ABYTES);
                let res = unsafe { crypto_aead_aes256gcm_encrypt_afternm(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut clen, // Mutable size of buffer (will be set to used size)
                    buf.as_ptr(), // Base pointer to message
                    mlen as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    ptr::null::<[u8; 0]>(), // Base pointer to secret nonce (always NULL)
                    nonce.as_ptr() as *const [u8; crypto_aead_aes256gcm_NPUBBYTES], // Base pointer to public nonce
                    state.0 // Base pointer to state
                ) };
                assert_eq!(res, 0);
                unsafe {
                    ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_bytes.as_mut_ptr(), nonce.len());
                }
                clen as usize
            }
        }
    }
}
