#[cfg(feature = "crypto")] mod sodium;
#[cfg(not(feature = "crypto"))] mod dummy;

#[cfg(feature = "crypto")] pub use self::sodium::Crypto;
#[cfg(not(feature = "crypto"))] pub use self::dummy::Crypto;
