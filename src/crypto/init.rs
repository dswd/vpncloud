// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

// This module implements a 3-way handshake to initialize an authenticated and encrypted connection.
//
// The handshake assumes that each node has a asymmetric Curve 25519 key pair as well as a list of trusted public keys
// and a set of supported crypto algorithms as well as the expected speed when using them. If successful, the handshake
// will negotiate a crypto algorithm to use and a common ephemeral symmetric key and exchange a given payload between
// the nodes.
//
// The handshake consists of 3 stages, "ping", "pong" and "peng". In the following description, the node that initiates
// the connection is named "A" and the other node is named "B". Since a lot of things are going on in parallel in the
// handshake, those aspects are described separately in the following paragraphs.
//
// Every message contains the node id of the sender. If a node receives a message with its own node id, it just ignores
// it and closes the connection. This is the way nodes avoid to connect to themselves as it is not trivial for a node
// to know its own addresses (especially in the case of NAT).
//
// All initialization messages are signed by the asymmetric key of the sender. Also the messages indicate the public
// key being used, so the receiver can use the correct public key to verify the signature. The public key itself is not
// attached to the message for privacy reasons (the public key is stable over multiple restarts while the node id is
// only valid for a single run). Instead, a 2 byte salt value as well as the last 2 bytes of the salted sha 2 hash of
// the public key are used to identify the public key. This way, a receiver that trusts this public key can identify
// it but a random observer can't. If the public key is unknown or the signature can't be verified, the message is
// ignored.
//
// Every message contains a byte that specifies the stage (ping = 1, pong = 2, peng = 3). If a message with an
// unexpected stage is received, it is ignored and the last message that has been sent is repeated. There is only one
// exception to this rule: if a "pong" message is expected, but a "ping" message is received instead AND the node id of
// the sender is greater than the node id of the receiver, the receiving node will reset its state and assume the role
// of a receiver of the initialization (i.e. "B"). This is used to "negotiate" the roles A and B when both nodes
// initiate the connection in parallel and think they are A.
//
// Upon connection creation, both nodes create a random ephemeral ECDH key pair and exchange the public keys in the
// ping and pong messages. A sends the ping message to B containing A's public key and B replies with a pong message
// containing B's public key. That means, that after receiving the ping message B can calculate the shared key material
// and after receiving the pong message A can calculate the shared key material.
//
// The ping message and the pong message contain a set of supported crypto algorithms together with the estimated
// speeds of the algorithms. When B receives a ping message, or A receives a pong message, it can combine this
// information with its own algorithm list and select the algorithm with the best expected speed for the crypto core.
//
// The pong and peng message contain the payload that the nodes want to exchange in the initialization phase apart from
// the cryptographic initialization. This payload is encoded according to the application and encrypted using the key
// material and the crypto algorithm that have been negotiated via the ping and pong messages. The pong message,
// therefore contains information to set up symmetric encryption as well as a part that is already encrypted.
//
// The handshake ends for A after sending the peng message and for B after receiving this message. At this time both
// nodes initialize the connection using the payload and enter normal operation. The negotiated crypto core is used for
// future communication and the key rotation is started. Since the peng message can be lost, A needs to keep the
// initialization state in order to repeat a lost peng message. After one second, A removes that state.
//
// Once every second, both nodes check whether they have already finished the initialization. If not, they repeat their
// last message. After 5 seconds, the initialization is aborted as failed.

use super::{
    core::{CryptoCore, EXTRA_LEN},
    Algorithms, EcdhPrivateKey, EcdhPublicKey, Ed25519PublicKey, Payload,
};
use crate::{error::Error, types::NodeId, util::MsgBuffer};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use ring::{
    aead::{Algorithm, LessSafeKey, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
    agreement::{agree_ephemeral, X25519},
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair, ED25519, ED25519_PUBLIC_KEY_LEN},
};
use smallvec::{smallvec, SmallVec};
use std::{
    cmp, f32,
    fmt::Debug,
    io::{self, Cursor, Read, Write},
    sync::Arc,
};

pub const STAGE_PING: u8 = 1;
pub const STAGE_PONG: u8 = 2;
pub const STAGE_PENG: u8 = 3;
pub const WAITING_TO_CLOSE: u8 = 4;
pub const CLOSING: u8 = 5;

pub const MAX_FAILED_RETRIES: usize = 120;

pub const SALTED_NODE_ID_HASH_LEN: usize = 20;
pub type SaltedNodeIdHash = [u8; SALTED_NODE_ID_HASH_LEN];

#[allow(clippy::large_enum_variant)]
pub enum InitMsg {
    Ping {
        salted_node_id_hash: SaltedNodeIdHash,
        ecdh_public_key: EcdhPublicKey,
        algorithms: Algorithms,
    },
    Pong {
        salted_node_id_hash: SaltedNodeIdHash,
        ecdh_public_key: EcdhPublicKey,
        algorithms: Algorithms,
        encrypted_payload: MsgBuffer,
    },
    Peng {
        salted_node_id_hash: SaltedNodeIdHash,
        encrypted_payload: MsgBuffer,
    },
}

impl InitMsg {
    const PART_ALGORITHMS: u8 = 4;
    const PART_ECDH_PUBLIC_KEY: u8 = 3;
    const PART_END: u8 = 0;
    const PART_PAYLOAD: u8 = 5;
    const PART_SALTED_NODE_ID_HASH: u8 = 2;
    const PART_STAGE: u8 = 1;

    fn stage(&self) -> u8 {
        match self {
            InitMsg::Ping { .. } => STAGE_PING,
            InitMsg::Pong { .. } => STAGE_PONG,
            InitMsg::Peng { .. } => STAGE_PENG,
        }
    }

    fn salted_node_id_hash(&self) -> &SaltedNodeIdHash {
        match self {
            InitMsg::Ping { salted_node_id_hash, .. }
            | InitMsg::Pong { salted_node_id_hash, .. }
            | InitMsg::Peng { salted_node_id_hash, .. } => salted_node_id_hash,
        }
    }

    fn calculate_hash(key: &Ed25519PublicKey, salt: &[u8; 4]) -> [u8; 4] {
        let mut data = [0; ED25519_PUBLIC_KEY_LEN + 4];
        data[..ED25519_PUBLIC_KEY_LEN].clone_from_slice(key);
        data[ED25519_PUBLIC_KEY_LEN..].clone_from_slice(salt);
        let hash = digest::digest(&digest::SHA256, &data);
        let mut short_hash = [0; 4];
        short_hash.clone_from_slice(&hash.as_ref()[..4]);
        short_hash
    }

    fn read_from(buffer: &[u8], trusted_keys: &[Ed25519PublicKey]) -> Result<(Self, Ed25519PublicKey), Error> {
        let mut r = Cursor::new(buffer);

        let mut public_key_salt = [0; 4];
        r.read_exact(&mut public_key_salt).map_err(|_| Error::Parse("Init message too short"))?;
        let mut public_key_hash = [0; 4];
        r.read_exact(&mut public_key_hash).map_err(|_| Error::Parse("Init message too short"))?;
        let mut public_key_data = [0; ED25519_PUBLIC_KEY_LEN];
        let mut found_key = false;
        for tk in trusted_keys {
            if Self::calculate_hash(tk, &public_key_salt) == public_key_hash {
                public_key_data.clone_from_slice(tk);
                found_key = true;
                break;
            }
        }
        if !found_key {
            return Err(Error::Crypto("untrusted peer"));
        }

        let mut stage = None;
        let mut salted_node_id_hash = None;
        let mut ecdh_public_key = None;
        let mut encrypted_payload = None;
        let mut algorithms = None;

        loop {
            let field = r.read_u8().map_err(|_| Error::Parse("Init message too short"))?;
            if field == Self::PART_END {
                break;
            }
            let field_len = r.read_u16::<NetworkEndian>().map_err(|_| Error::Parse("Init message too short"))? as usize;
            match field {
                Self::PART_STAGE => {
                    if field_len != 1 {
                        return Err(Error::CryptoInit("Invalid size for stage field"));
                    }
                    stage = Some(r.read_u8().map_err(|_| Error::Parse("Init message too short"))?)
                }
                Self::PART_SALTED_NODE_ID_HASH => {
                    if field_len != SALTED_NODE_ID_HASH_LEN {
                        return Err(Error::CryptoInit("Invalid size for salted node id hash field"));
                    }
                    let mut id = [0; SALTED_NODE_ID_HASH_LEN];
                    r.read_exact(&mut id).map_err(|_| Error::Parse("Init message too short"))?;
                    salted_node_id_hash = Some(id)
                }
                Self::PART_ECDH_PUBLIC_KEY => {
                    let mut pub_key_data = smallvec![0; field_len];
                    r.read_exact(&mut pub_key_data).map_err(|_| Error::Parse("Init message too short"))?;
                    ecdh_public_key = Some(EcdhPublicKey::new(&X25519, pub_key_data));
                }
                Self::PART_PAYLOAD => {
                    let mut payload = MsgBuffer::new(0);
                    payload.set_length(field_len);
                    r.read_exact(payload.message_mut()).map_err(|_| Error::Parse("Init message too short"))?;
                    encrypted_payload = Some(payload);
                }
                Self::PART_ALGORITHMS => {
                    let count = field_len / 5;
                    let mut algos = SmallVec::with_capacity(count);
                    let mut allow_unencrypted = false;
                    for _ in 0..count {
                        let algo = match r.read_u8().map_err(|_| Error::Parse("Init message too short"))? {
                            0 => {
                                allow_unencrypted = true;
                                None
                            }
                            1 => Some(&AES_128_GCM),
                            2 => Some(&AES_256_GCM),
                            3 => Some(&CHACHA20_POLY1305),
                            _ => None,
                        };
                        let speed =
                            r.read_f32::<NetworkEndian>().map_err(|_| Error::Parse("Init message too short"))?;
                        if let Some(algo) = algo {
                            algos.push((algo, speed));
                        }
                    }
                    algorithms = Some(Algorithms { algorithm_speeds: algos, allow_unencrypted });
                }
                _ => {
                    let mut data = vec![0; field_len];
                    r.read_exact(&mut data).map_err(|_| Error::Parse("Init message too short"))?;
                }
            }
        }

        let pos = r.position() as usize;

        let signature_len = r.read_u8().map_err(|_| Error::Parse("Init message too short"))? as usize;
        let mut signature: SmallVec<[u8; 32]> = smallvec![0; signature_len];
        r.read_exact(&mut signature).map_err(|_| Error::Parse("Init message too short"))?;

        let signed_data = &r.into_inner()[0..pos];
        let public_key = signature::UnparsedPublicKey::new(&ED25519, &public_key_data);
        if public_key.verify(signed_data, &signature).is_err() {
            return Err(Error::Crypto("invalid signature"));
        }

        let stage = match stage {
            Some(val) => val,
            None => return Err(Error::CryptoInit("Init message without stage")),
        };
        let salted_node_id_hash = match salted_node_id_hash {
            Some(val) => val,
            None => return Err(Error::CryptoInit("Init message without node id")),
        };

        let msg = match stage {
            STAGE_PING => {
                let ecdh_public_key = match ecdh_public_key {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without ecdh public key")),
                };
                let algorithms = match algorithms {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without algorithms")),
                };
                Self::Ping { salted_node_id_hash, ecdh_public_key, algorithms }
            }
            STAGE_PONG => {
                let ecdh_public_key = match ecdh_public_key {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without ecdh public key")),
                };
                let algorithms = match algorithms {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without algorithms")),
                };
                let encrypted_payload = match encrypted_payload {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without payload")),
                };
                Self::Pong { salted_node_id_hash, ecdh_public_key, algorithms, encrypted_payload }
            }
            STAGE_PENG => {
                let encrypted_payload = match encrypted_payload {
                    Some(val) => val,
                    None => return Err(Error::CryptoInit("Init message without payload")),
                };
                Self::Peng { salted_node_id_hash, encrypted_payload }
            }
            _ => return Err(Error::CryptoInit("Invalid stage")),
        };

        Ok((msg, public_key_data))
    }

    fn write_to(&self, buffer: &mut [u8], key: &Ed25519KeyPair) -> Result<usize, io::Error> {
        let mut w = Cursor::new(buffer);

        let rand = SystemRandom::new();
        let mut salt = [0; 4];
        rand.fill(&mut salt).unwrap();
        let mut public_key = [0; ED25519_PUBLIC_KEY_LEN];
        public_key.clone_from_slice(key.public_key().as_ref());
        let hash = Self::calculate_hash(&public_key, &salt);
        w.write_all(&salt)?;
        w.write_all(&hash)?;

        w.write_u8(Self::PART_STAGE)?;
        w.write_u16::<NetworkEndian>(1)?;
        w.write_u8(self.stage())?;

        match &self {
            Self::Ping { salted_node_id_hash, .. }
            | Self::Pong { salted_node_id_hash, .. }
            | Self::Peng { salted_node_id_hash, .. } => {
                w.write_u8(Self::PART_SALTED_NODE_ID_HASH)?;
                w.write_u16::<NetworkEndian>(SALTED_NODE_ID_HASH_LEN as u16)?;
                w.write_all(salted_node_id_hash)?;
            }
        }

        match &self {
            Self::Ping { ecdh_public_key, .. } | Self::Pong { ecdh_public_key, .. } => {
                w.write_u8(Self::PART_ECDH_PUBLIC_KEY)?;
                let key_bytes = ecdh_public_key.bytes();
                w.write_u16::<NetworkEndian>(key_bytes.len() as u16)?;
                w.write_all(key_bytes)?;
            }
            _ => (),
        }

        match &self {
            Self::Ping { algorithms, .. } | Self::Pong { algorithms, .. } => {
                w.write_u8(Self::PART_ALGORITHMS)?;
                let mut len = algorithms.algorithm_speeds.len() * 5;
                if algorithms.allow_unencrypted {
                    len += 5;
                }
                w.write_u16::<NetworkEndian>(len as u16)?;
                if algorithms.allow_unencrypted {
                    w.write_u8(0)?;
                    w.write_f32::<NetworkEndian>(f32::INFINITY)?;
                }
                for (algo, speed) in &algorithms.algorithm_speeds {
                    if *algo == &AES_128_GCM {
                        w.write_u8(1)?;
                    } else if *algo == &AES_256_GCM {
                        w.write_u8(2)?;
                    } else if *algo == &CHACHA20_POLY1305 {
                        w.write_u8(3)?;
                    } else {
                        unreachable!();
                    }
                    w.write_f32::<NetworkEndian>(*speed)?;
                }
            }
            _ => (),
        }

        match &self {
            Self::Pong { encrypted_payload, .. } | Self::Peng { encrypted_payload, .. } => {
                w.write_u8(Self::PART_PAYLOAD)?;
                w.write_u16::<NetworkEndian>(encrypted_payload.len() as u16)?;
                w.write_all(encrypted_payload.message())?;
            }
            _ => (),
        }

        w.write_u8(Self::PART_END)?;

        let pos = w.position() as usize;
        let signature = key.sign(&w.get_ref()[0..pos]);
        w.write_u8(signature.as_ref().len() as u8)?;
        w.write_all(signature.as_ref())?;

        Ok(w.position() as usize)
    }
}

#[derive(PartialEq, Debug)]
pub enum InitResult<P: Payload> {
    Continue,
    Success { peer_payload: P, is_initiator: bool },
}

pub struct InitState<P: Payload> {
    node_id: NodeId,
    salted_node_id_hash: SaltedNodeIdHash,
    payload: P,
    key_pair: Arc<Ed25519KeyPair>,
    trusted_keys: Arc<[Ed25519PublicKey]>,
    ecdh_private_key: Option<EcdhPrivateKey>,
    next_stage: u8,
    close_time: usize,
    last_message: Option<Vec<u8>>,
    crypto: Option<CryptoCore>,
    algorithms: Algorithms,
    #[allow(dead_code)] // Used in tests
    selected_algorithm: Option<&'static Algorithm>,
    failed_retries: usize,
}

impl<P: Payload> InitState<P> {
    pub fn new(
        node_id: NodeId, payload: P, key_pair: Arc<Ed25519KeyPair>, trusted_keys: Arc<[Ed25519PublicKey]>,
        algorithms: Algorithms,
    ) -> Self {
        let mut hash = [0; SALTED_NODE_ID_HASH_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut hash[0..4]).unwrap();
        hash[4..].clone_from_slice(&node_id);
        let d = digest::digest(&digest::SHA256, &hash);
        hash[4..].clone_from_slice(&d.as_ref()[..16]);
        Self {
            node_id,
            salted_node_id_hash: hash,
            payload,
            key_pair,
            trusted_keys,
            next_stage: STAGE_PING,
            last_message: None,
            crypto: None,
            ecdh_private_key: None,
            selected_algorithm: None,
            algorithms,
            failed_retries: 0,
            close_time: 60,
        }
    }

    pub fn send_ping(&mut self, out: &mut MsgBuffer) {
        // create ecdh ephemeral key
        let (ecdh_private_key, ecdh_public_key) = self.create_ecdh_keypair();
        self.ecdh_private_key = Some(ecdh_private_key);

        // create stage 1 msg
        self.send_message(STAGE_PING, Some(ecdh_public_key), out);

        self.next_stage = STAGE_PONG;
    }

    pub fn stage(&self) -> u8 {
        self.next_stage
    }

    pub fn every_second(&mut self, out: &mut MsgBuffer) -> Result<(), Error> {
        if self.next_stage == WAITING_TO_CLOSE {
            if self.close_time == 0 {
                self.next_stage = CLOSING;
            } else {
                self.close_time -= 1;
            }
            Ok(())
        } else if self.next_stage == CLOSING {
            Ok(())
        } else if self.failed_retries < MAX_FAILED_RETRIES {
            self.failed_retries += 1;
            self.repeat_last_message(out);
            Ok(())
        } else {
            self.next_stage = CLOSING;
            Err(Error::CryptoInitFatal("Initialization timeout"))
        }
    }

    fn derive_master_key(&self, algo: &'static Algorithm, privk: EcdhPrivateKey, pubk: &EcdhPublicKey) -> LessSafeKey {
        agree_ephemeral(privk, pubk, (), |k| {
            UnboundKey::new(algo, &k[..algo.key_len()]).map(LessSafeKey::new).map_err(|_| ())
        })
        .unwrap()
    }

    fn create_ecdh_keypair(&self) -> (EcdhPrivateKey, EcdhPublicKey) {
        let rand = SystemRandom::new();
        let ecdh_private_key = EcdhPrivateKey::generate(&X25519, &rand).unwrap();
        let public_key = ecdh_private_key.compute_public_key().unwrap();
        let mut vec = SmallVec::<[u8; 96]>::new();
        vec.extend_from_slice(public_key.as_ref());
        let ecdh_public_key = EcdhPublicKey::new(&X25519, vec);
        (ecdh_private_key, ecdh_public_key)
    }

    fn encrypt_payload(&mut self) -> MsgBuffer {
        let mut buffer = MsgBuffer::new(EXTRA_LEN);
        self.payload.write_to(&mut buffer);
        if let Some(crypto) = &mut self.crypto {
            crypto.encrypt(&mut buffer);
        }
        buffer
    }

    fn decrypt(&mut self, data: &mut MsgBuffer) -> Result<P, Error> {
        if let Some(crypto) = &mut self.crypto {
            crypto.decrypt(data)?;
        }
        P::read_from(Cursor::new(data.message()))
    }

    fn check_salted_node_id_hash(&self, hash: &SaltedNodeIdHash, node_id: NodeId) -> bool {
        let mut h2 = [0; SALTED_NODE_ID_HASH_LEN];
        h2[0..4].clone_from_slice(&hash[0..4]);
        h2[4..].clone_from_slice(&node_id);
        let d = digest::digest(&digest::SHA256, &h2);
        hash == d.as_ref()
    }

    fn send_message(&mut self, stage: u8, ecdh_public_key: Option<EcdhPublicKey>, out: &mut MsgBuffer) {
        debug!("Sending init with stage={}", stage);
        assert!(out.is_empty());
        let mut public_key = [0; ED25519_PUBLIC_KEY_LEN];
        public_key.clone_from_slice(self.key_pair.as_ref().public_key().as_ref());
        let msg = match stage {
            STAGE_PING => InitMsg::Ping {
                salted_node_id_hash: self.salted_node_id_hash,
                ecdh_public_key: ecdh_public_key.unwrap(),
                algorithms: self.algorithms.clone(),
            },
            STAGE_PONG => InitMsg::Pong {
                salted_node_id_hash: self.salted_node_id_hash,
                ecdh_public_key: ecdh_public_key.unwrap(),
                algorithms: self.algorithms.clone(),
                encrypted_payload: self.encrypt_payload(),
            },
            STAGE_PENG => InitMsg::Peng {
                salted_node_id_hash: self.salted_node_id_hash,
                encrypted_payload: self.encrypt_payload(),
            },
            _ => unreachable!(),
        };
        let bytes = out.buffer();
        let len = msg.write_to(bytes, &self.key_pair).expect("Buffer too small");
        self.last_message = Some(bytes[0..len].to_vec());
        out.set_length(len);
    }

    fn repeat_last_message(&self, out: &mut MsgBuffer) {
        if let Some(ref bytes) = self.last_message {
            debug!("Repeating last init message");
            let buffer = out.buffer();
            buffer[0..bytes.len()].copy_from_slice(bytes);
            out.set_length(bytes.len());
        }
    }

    fn select_algorithm(&self, peer_algos: &Algorithms) -> Result<Option<(&'static Algorithm, f32)>, Error> {
        if self.algorithms.allow_unencrypted && peer_algos.allow_unencrypted {
            return Ok(None);
        }
        // For each supported algorithm, find the algorithm in the list of the peer (ignore algorithm if not found).
        // Take the minimal speed reported by either us or the peer.
        // Select the algorithm with the greatest minimal speed.
        let algo = self
            .algorithms
            .algorithm_speeds
            .iter()
            .filter_map(|(a1, s1)| {
                peer_algos
                    .algorithm_speeds
                    .iter()
                    .find(|(a2, _)| a1 == a2)
                    .map(|(_, s2)| (*a1, if s1 < s2 { *s1 } else { *s2 }))
            })
            .max_by(|(_, s1), (_, s2)| if s1 < s2 { cmp::Ordering::Less } else { cmp::Ordering::Greater });
        if let Some(algo) = algo {
            debug!("Init: best algorithm is {:?} with speed {}", algo.0, algo.1);
            Ok(Some(algo))
        } else {
            Err(Error::CryptoInitFatal("No common algorithms"))
        }
    }

    pub fn handle_init(&mut self, out: &mut MsgBuffer) -> Result<InitResult<P>, Error> {
        let (msg, _peer_key) = InitMsg::read_from(out.buffer(), &self.trusted_keys)?;
        out.clear();
        let stage = msg.stage();
        let salted_node_id_hash = *msg.salted_node_id_hash();
        debug!("Received init with stage={}, expected stage={}", stage, self.next_stage);
        if self.salted_node_id_hash == salted_node_id_hash
            || self.check_salted_node_id_hash(&salted_node_id_hash, self.node_id)
        {
            return Err(Error::CryptoInitFatal("Connected to self"));
        }
        if stage != self.next_stage {
            if self.next_stage == STAGE_PONG && stage == STAGE_PING {
                // special case for concurrent init messages in both directions
                // the node with the higher node_id "wins" and gets to initialize the connection
                if salted_node_id_hash > self.salted_node_id_hash {
                    // reset to initial state
                    self.next_stage = STAGE_PING;
                    self.last_message = None;
                    self.ecdh_private_key = None;
                } else {
                    return Ok(InitResult::Continue);
                }
            } else if self.next_stage == CLOSING {
                return Ok(InitResult::Continue);
            } else if self.last_message.is_some() {
                self.repeat_last_message(out);
                return Ok(InitResult::Continue);
            } else {
                return Err(Error::CryptoInitFatal("Received invalid stage as first message"));
            }
        }
        self.failed_retries = 0;
        match msg {
            InitMsg::Ping { ecdh_public_key, algorithms, .. } => {
                // create ecdh ephemeral key
                let (my_ecdh_private_key, my_ecdh_public_key) = self.create_ecdh_keypair();

                // do ecdh agreement and derive master key
                let algorithm = self.select_algorithm(&algorithms)?;
                self.selected_algorithm = algorithm.map(|a| a.0);
                if let Some((algorithm, _speed)) = algorithm {
                    let master_key = self.derive_master_key(algorithm, my_ecdh_private_key, &ecdh_public_key);
                    self.crypto = Some(CryptoCore::new(master_key, self.salted_node_id_hash > salted_node_id_hash));
                }

                // create and send stage 2 reply
                self.send_message(STAGE_PONG, Some(my_ecdh_public_key), out);

                self.next_stage = STAGE_PENG;
                Ok(InitResult::Continue)
            }
            InitMsg::Pong { ecdh_public_key, algorithms, mut encrypted_payload, .. } => {
                // do ecdh agreement and derive master key
                let ecdh_private_key = self.ecdh_private_key.take().unwrap();
                let algorithm = self.select_algorithm(&algorithms)?;
                self.selected_algorithm = algorithm.map(|a| a.0);
                if let Some((algorithm, _speed)) = algorithm {
                    let master_key = self.derive_master_key(algorithm, ecdh_private_key, &ecdh_public_key);
                    self.crypto = Some(CryptoCore::new(master_key, self.salted_node_id_hash > salted_node_id_hash));
                }

                // decrypt the payload
                let peer_payload = self
                    .decrypt(&mut encrypted_payload)
                    .map_err(|_| Error::CryptoInitFatal("Failed to decrypt payload"))?;

                // create and send stage 3 reply
                self.send_message(STAGE_PENG, None, out);

                self.next_stage = WAITING_TO_CLOSE;
                self.close_time = 60;
                Ok(InitResult::Success { peer_payload, is_initiator: true })
            }
            InitMsg::Peng { mut encrypted_payload, .. } => {
                // decrypt the payload
                let peer_payload = self
                    .decrypt(&mut encrypted_payload)
                    .map_err(|_| Error::CryptoInitFatal("Failed to decrypt payload"))?;

                self.next_stage = CLOSING; // force resend when receiving any message
                Ok(InitResult::Success { peer_payload, is_initiator: false })
            }
        }
    }

    pub fn take_core(&mut self) -> Option<CryptoCore> {
        self.crypto.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NODE_ID_BYTES;

    impl Payload for Vec<u8> {
        fn write_to(&self, buffer: &mut MsgBuffer) {
            buffer.buffer().write_all(self).expect("Buffer too small");
            buffer.set_length(self.len())
        }

        fn read_from<R: Read>(mut r: R) -> Result<Self, Error> {
            let mut data = Vec::new();
            r.read_to_end(&mut data).map_err(|_| Error::Parse("Buffer too small"))?;
            Ok(data)
        }
    }

    fn create_pair() -> (InitState<Vec<u8>>, InitState<Vec<u8>>) {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Arc::new(Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap());
        let mut public_key = [0; ED25519_PUBLIC_KEY_LEN];
        public_key.clone_from_slice(key_pair.public_key().as_ref());
        let trusted_nodes = Arc::new([public_key]);
        let mut node1 = [0; NODE_ID_BYTES];
        rng.fill(&mut node1).unwrap();
        let mut node2 = [0; NODE_ID_BYTES];
        rng.fill(&mut node2).unwrap();
        let algorithms = Algorithms {
            algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
            allow_unencrypted: false,
        };
        let sender = InitState::new(node1, vec![1], key_pair.clone(), trusted_nodes.clone(), algorithms.clone());
        let receiver = InitState::new(node2, vec![2], key_pair, trusted_nodes, algorithms);
        (sender, receiver)
    }

    #[test]
    fn normal_init() {
        let (mut sender, mut receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        let result = receiver.handle_init(&mut out).unwrap();
        assert_eq!(receiver.stage(), STAGE_PENG);
        assert_eq!(result, InitResult::Continue);
        let result = sender.handle_init(&mut out).unwrap();
        assert_eq!(sender.stage(), WAITING_TO_CLOSE);
        let result = match result {
            InitResult::Success { .. } => receiver.handle_init(&mut out).unwrap(),
            InitResult::Continue => unreachable!(),
        };
        assert_eq!(receiver.stage(), CLOSING);
        match result {
            InitResult::Success { .. } => assert!(out.is_empty()),
            InitResult::Continue => unreachable!(),
        }
    }

    #[test]
    fn lost_init_sender_recovers() {
        let (mut sender, mut receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        // lost ping, sender recovers
        out.clear();
        sender.every_second(&mut out).unwrap();
        let result = receiver.handle_init(&mut out).unwrap();
        assert_eq!(receiver.stage(), STAGE_PENG);
        assert_eq!(result, InitResult::Continue);
        // lost pong, sender recovers
        out.clear();
        receiver.every_second(&mut out).unwrap();
        let result = sender.handle_init(&mut out).unwrap();
        assert_eq!(sender.stage(), WAITING_TO_CLOSE);
        match result {
            InitResult::Success { .. } => {
                // lost peng, sender recovers
                out.clear();
            }
            InitResult::Continue => unreachable!(),
        };
        sender.every_second(&mut out).unwrap();
        let result = receiver.handle_init(&mut out).unwrap();
        assert_eq!(receiver.stage(), CLOSING);
        match result {
            InitResult::Success { .. } => assert!(out.is_empty()),
            InitResult::Continue => unreachable!(),
        }
    }

    #[test]
    fn lost_init_receiver_recovers() {
        let (mut sender, mut receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        let result = receiver.handle_init(&mut out).unwrap();
        assert_eq!(receiver.stage(), STAGE_PENG);
        assert_eq!(result, InitResult::Continue);
        // lost pong, receiver recovers
        out.clear();
        sender.every_second(&mut out).unwrap();
        receiver.handle_init(&mut out).unwrap();
        let result = sender.handle_init(&mut out).unwrap();
        assert_eq!(sender.stage(), WAITING_TO_CLOSE);
        match result {
            InitResult::Success { .. } => {
                // lost peng, sender recovers
                out.clear();
            }
            InitResult::Continue => unreachable!(),
        };
        receiver.every_second(&mut out).unwrap();
        sender.handle_init(&mut out).unwrap();
        let result = receiver.handle_init(&mut out).unwrap();
        assert_eq!(receiver.stage(), CLOSING);
        match result {
            InitResult::Success { .. } => assert!(out.is_empty()),
            InitResult::Continue => unreachable!(),
        }
    }

    #[test]
    fn timeout() {
        let (mut sender, _receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        for _ in 0..120 {
            out.clear();
            sender.every_second(&mut out).unwrap();
        }
        out.clear();
        assert!(sender.every_second(&mut out).is_err());
        assert_eq!(sender.stage(), CLOSING);
    }

    #[test]
    fn untrusted_peer() {
        let (mut sender, _) = create_pair();
        let (_, mut receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        assert!(receiver.handle_init(&mut out).is_err());
    }

    #[test]
    fn manipulated_message() {
        let (mut sender, mut receiver) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        out.message_mut()[10] ^= 0x01;
        assert!(receiver.handle_init(&mut out).is_err());
    }

    #[test]
    fn connect_to_self() {
        let (mut sender, _) = create_pair();
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        assert_eq!(sender.stage(), STAGE_PONG);
        assert!(sender.handle_init(&mut out).is_err());
    }

    fn test_algorithm_negotiation(
        algos1: Algorithms, algos2: Algorithms, success: bool, selected: Option<&'static Algorithm>,
    ) {
        let (mut sender, mut receiver) = create_pair();
        sender.algorithms = algos1;
        receiver.algorithms = algos2;
        let mut out = MsgBuffer::new(8);
        sender.send_ping(&mut out);
        let res = receiver.handle_init(&mut out);
        assert_eq!(res.is_ok(), success);
        if !success {
            return;
        }
        sender.handle_init(&mut out).unwrap();
        receiver.handle_init(&mut out).unwrap();
        assert_eq!(sender.selected_algorithm, selected);
        assert_eq!(sender.selected_algorithm, receiver.selected_algorithm);
    }

    #[test]
    fn algorithm_negotiation() {
        // Equal algorithms
        test_algorithm_negotiation(
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            true,
            Some(&AES_128_GCM),
        );

        // Overlapping but different
        test_algorithm_negotiation(
            Algorithms {
                algorithm_speeds: smallvec![(&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0)],
                allow_unencrypted: false,
            },
            true,
            Some(&AES_256_GCM),
        );

        // Select fastest pair
        test_algorithm_negotiation(
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 40.0), (&AES_256_GCM, 50.0), (&CHACHA20_POLY1305, 60.0)],
                allow_unencrypted: false,
            },
            true,
            Some(&CHACHA20_POLY1305),
        );

        // Select unencrypted if supported by both
        test_algorithm_negotiation(
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: true,
            },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: true,
            },
            true,
            None,
        );

        // Do not select unencrypted if only supported by one
        test_algorithm_negotiation(
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: true,
            },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_128_GCM, 600.0), (&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            true,
            Some(&AES_128_GCM),
        );

        // Fail if no match
        test_algorithm_negotiation(
            Algorithms { algorithm_speeds: smallvec![(&AES_128_GCM, 600.0)], allow_unencrypted: true },
            Algorithms {
                algorithm_speeds: smallvec![(&AES_256_GCM, 500.0), (&CHACHA20_POLY1305, 400.0)],
                allow_unencrypted: false,
            },
            false,
            Some(&AES_128_GCM),
        );
    }
}
