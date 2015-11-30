use std::{mem, ptr};
use std::ffi::CStr;

use libc::{size_t, c_char, c_ulonglong, c_int};

use super::types::Error;

#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_KEYBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_NSECBYTES: usize = 0;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_NPUBBYTES: usize = 8;
#[allow(non_upper_case_globals)]
const crypto_aead_chacha20poly1305_ABYTES: usize = 16;

#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_KEYBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_NSECBYTES: usize = 0;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_NPUBBYTES: usize = 12;
#[allow(non_upper_case_globals)]
const crypto_aead_aes256gcm_ABYTES: usize = 16;

#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: usize = 32;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_STRBYTES: usize = 102;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: usize = 524288;
#[allow(non_upper_case_globals)]
const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: usize = 16777216;

#[link(name="sodium", kind="static")]
extern {
    pub fn sodium_init() -> c_int;
    pub fn randombytes_buf(buf: *mut u8, size: size_t);
    pub fn sodium_version_string() -> *const c_char;
    pub fn crypto_pwhash_scryptsalsa208sha256(
        out: *mut u8,
        outlen: c_ulonglong,
        passwd: *const u8,
        passwdlen: c_ulonglong,
        salt: *const [u8; crypto_pwhash_scryptsalsa208sha256_SALTBYTES],
        opslimit: c_ulonglong,
        memlimit: size_t) -> c_int;
    pub fn crypto_aead_chacha20poly1305_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_chacha20poly1305_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_chacha20poly1305_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_chacha20poly1305_NPUBBYTES],
        k: *const [u8; crypto_aead_chacha20poly1305_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_encrypt(
        c: *mut u8,
        clen: *mut c_ulonglong,
        m: *const u8,
        mlen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        nsec: *const [u8; crypto_aead_aes256gcm_NSECBYTES],
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
    pub fn crypto_aead_aes256gcm_decrypt(
        m: *mut u8,
        mlen: *mut c_ulonglong,
        nsec: *mut [u8; crypto_aead_aes256gcm_NSECBYTES],
        c: *const u8,
        clen: c_ulonglong,
        ad: *const u8,
        adlen: c_ulonglong,
        npub: *const [u8; crypto_aead_aes256gcm_NPUBBYTES],
        k: *const [u8; crypto_aead_aes256gcm_KEYBYTES]) -> c_int;
}


#[derive(RustcDecodable, Debug)]
pub enum CryptoMethod {
    ChaCha20, AES256
}

pub enum Crypto {
    None,
    ChaCha20Poly1305{key: [u8; 32], nonce: [u8; 8]},
    AES256GCM{key: [u8; 32], nonce: [u8; 12]}
}

fn inc_nonce_8(nonce: &mut [u8; 8]) {
    unsafe {
        let num = mem::transmute::<&mut [u8; 8], &mut u64>(nonce);
        *num = num.wrapping_add(1)
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
    pub fn init() {
        unsafe { sodium_init() };
    }

    pub fn sodium_version() -> String {
        unsafe {
            CStr::from_ptr(sodium_version_string()).to_string_lossy().to_string()
        }
    }

    pub fn method(&self) -> u8 {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, nonce: _} => 1,
            &Crypto::AES256GCM{key: _, nonce: _} => 2
        }
    }

    pub fn nonce_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, ref nonce} => nonce.len(),
            &Crypto::AES256GCM{key: _, ref nonce} => nonce.len()
        }
    }

    pub fn additional_bytes(&self) -> usize {
        match self {
            &Crypto::None => 0,
            &Crypto::ChaCha20Poly1305{key: _, nonce: _} => crypto_aead_chacha20poly1305_ABYTES,
            &Crypto::AES256GCM{key: _, nonce: _} => crypto_aead_aes256gcm_ABYTES
        }
    }

    pub fn from_shared_key(method: CryptoMethod, password: &str) -> Self {
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
        match method {
            CryptoMethod::ChaCha20 => {
                let mut crypto_key = [0; crypto_aead_chacha20poly1305_KEYBYTES];
                for i in 0..crypto_key.len() {
                    crypto_key[i] = key[i];
                }
                let mut nonce = [0u8; crypto_aead_chacha20poly1305_NPUBBYTES];
                unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
                Crypto::ChaCha20Poly1305{key: crypto_key, nonce: nonce}
            },
            CryptoMethod::AES256 => {
                let mut crypto_key = [0; crypto_aead_aes256gcm_KEYBYTES];
                for i in 0..crypto_key.len() {
                    crypto_key[i] = key[i];
                }
                let mut nonce = [0u8; crypto_aead_aes256gcm_NPUBBYTES];
                unsafe { randombytes_buf(nonce.as_mut_ptr(), nonce.len()) };
                Crypto::AES256GCM{key: crypto_key, nonce: nonce}
            }
        }
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
            },
            &Crypto::AES256GCM{ref key, nonce: _} => {
                let mut mlen: u64 = buf.len() as u64;
                let res = unsafe { crypto_aead_aes256gcm_decrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut mlen, // Mutable size of buffer (will be set to used size)
                    ptr::null_mut::<[u8; 0]>(), // Mutable base pointer to secret nonce (always NULL)
                    buf.as_ptr(), // Base pointer to message
                    buf.len() as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    nonce.as_ptr() as *const [u8; 12], // Base pointer to public nonce
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
                inc_nonce_8(nonce);
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
            },
            &mut Crypto::AES256GCM{ref key, ref mut nonce} => {
                inc_nonce_12(nonce);
                let mut clen: u64 = buf.len() as u64;
                assert_eq!(nonce_bytes.len(), nonce.len());
                assert_eq!(nonce.len(), crypto_aead_aes256gcm_NPUBBYTES);
                assert_eq!(key.len(), crypto_aead_aes256gcm_KEYBYTES);
                assert_eq!(0, crypto_aead_aes256gcm_NSECBYTES);
                assert!(clen as usize >= mlen + crypto_aead_aes256gcm_ABYTES);
                let res = unsafe { crypto_aead_aes256gcm_encrypt(
                    buf.as_mut_ptr(), // Base pointer to buffer
                    &mut clen, // Mutable size of buffer (will be set to used size)
                    buf.as_ptr(), // Base pointer to message
                    mlen as u64, // Size of message
                    header.as_ptr(), // Base pointer to additional data
                    header.len() as u64, // Size of additional data
                    ptr::null::<[u8; 0]>(), // Base pointer to secret nonce (always NULL)
                    nonce.as_ptr() as *const [u8; 12], // Base pointer to public nonce
                    key.as_ptr() as *const [u8; 32] // Base pointer to key
                ) };
                assert_eq!(res, 0);
                assert_eq!(clen as usize, mlen + crypto_aead_aes256gcm_ABYTES);
                unsafe {
                    ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_bytes.as_mut_ptr(), nonce.len());
                }
                clen as usize
            }
        }
    }
}
