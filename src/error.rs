use thiserror::Error;

use std::io;


#[derive(Error, Debug)]
pub enum Error {
    #[error("Unauthorized message: {0}")]
    Unauthorized(&'static str),

    #[error("Crypto initialization error: {0}")]
    CryptoInit(&'static str),

    #[error("Crypto error: {0}")]
    Crypto(&'static str),

    #[error("Invalid crypto state: {0}")]
    InvalidCryptoState(&'static str),

    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("Socker error: {0}")]
    Socket(&'static str),

    #[error("Socker error: {0}")]
    SocketIo(&'static str, #[source] io::Error),

    #[error("Device error: {0}")]
    Device(&'static str),

    #[error("Device error: {0}")]
    DeviceIo(&'static str, #[source] io::Error),

    #[error("File error: {0}")]
    FileIo(&'static str, #[source] io::Error),

    #[error("Message error: {0}")]
    Message(&'static str),

    #[error("Beacon error: {0}")]
    BeaconIo(&'static str, #[source] io::Error),

    #[error("Parse error: {0}")]
    Parse(&'static str),

    #[error("Name can not be resolved: {0}")]
    NameUnresolvable(String)
}
