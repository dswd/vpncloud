The following cryptographic communication protocol is inspired by the noise protocol but contains adaptations
* for accepting a set of public keys
* and to tolerate message reordering and loss during
* and for automatic rekeying


## Key pairs and trust

Each node has a key pair consisting of a public key P and a private key S.
Also each node has a set of trusted public keys of other nodes.

There are two ways configure the key pair and trusted keys:

shared secret mode) The key pair is derived from a secret string and the only trusted public key is the public key of the key pair itself.
In this mode, all nodes must be configured with the same shared secret and then derive the identical key pair and trust each others via the common public key.

explicit trust mode) The key pair is generated randomly on each node and stored in the config file of that node. The public keys of the other nodes are exchanged beforehand (not part of VpnCloud) and listed in the config file.

The key pair is only used during connection setup, all other messages are encrypted using short-lived keys derived from an ephemeral master key.


## Initial handshake

Upon establishing a connection, there will be a 3-way handshake during which a X25519 ECDH exchange happens. Here is some pseudo code to illustrate this:

fn connect(peer) {
    ecdh_keypair = create_new_ecdh_keypair()
    peer.ecdh_private_key = ecdh_keypair.private_key
    msg = Message (
        stage = 1, 
        node_id = self.node_id, 
        public_key = self.key_pair.public_key, 
        ecdh_public_key = ecdh_keypair.public_key,
    )
    msg_signed = self.key_pair.sign(msg)
    peer.next_stage = 2
    send_to(peer, msg_signed)
}

fn handle_init_message(peer, msg) {
    if msg.node_id == self.node_id {
        return
    }
    if !is_trusted(msg.public_key) {
        return
    }
    if !signature_valid(msg, msg.signature, msg.public_key) {
        return
    }
    if peer.next_stage == null {
        peer.next_stage = 1
    }
    if msg.stage != peer.next_stage && peer.last_msg != null {
        repeat_last_message_to(peer)
        return
    }
    if msg.stage == 1 {
        ecdh_keypair = create_new_ecdh_keypair()
        peer.master_key = ecdh_keypair.private_key.agree(msg.ecdh_public_key)
        peer.current_subkey = peer.master_key.derive_subkey(0)
        payload = { non-crypto init message }
        encrypted_payload = peer.current_subkey.encrypt(payload)
        msg = Message (
            stage = 2,
            node_id = self.node_id, 
            public_key = self.key_pair.public_key, 
            ecdh_public_key = ecdh_keypair.public_key,
            payload = encrypted_payload
        )
        msg_signed = self.key_pair.sign(msg)
        peer.next_stage = 3
        send_to(peer, msg_signed)
    }
    if msg.stage == 2 {
        peer.master_key = peer.ecdh_private_key.agree(msg.ecdh_public_key)
        peer.current_subkey = peer.master_key.derive_subkey(0)
        peer_payload = peer.current_subkey.decrypt(msg.payload)
        { use non-crypto payload }
        payload = { non-crypto init message }
        encrypted_payload = peer.current_subkey.encrypt(payload)
        msg = Message (
            stage = 3,
            node_id = self.node_id,
            public_key = self.key_pair.public_key,
            payload = encrypted_payload
        )
        msg_signed = self.key_pair.sign(msg)
        peer.next_stage = 1
        send_to(peer, msg_signed)
        { add peer to list, replace if needed }
    }
    if msg.stage == 3 {
        peer_payload = peer.current_subkey.decrypt(msg.payload)
        peer.next_stage = 1
        { use non-crypto payload }
        { add peer to list, replace if needed }
    }
}

In order to prevent denial-of-service attacks, established connections will only be affected when a message in stage 2 or 3 is received. This stage can not be reached by replaying messages.
If an initialization message at stage 1 is received without there being an active initialization state, a new state is created to handle the request. Messages with other stages are ignored.
If a message with an unexpected stage is received, the last sent initialization message is repeated.
After a timeout, e.g. 5 seconds, the last message is repeated if the connection is still in the initialization phase.


## Subkeys and key rotation

All messages except for the initialization handshake are encrypted using short-lived keys derived from the master key that is created during initialization.
The master key is never used for encryption. Instead it is used to derive subkeys that in turn are used for encryption. The subkeys are only temporary and are rotated periodically.
The challenge is to swap subkeys and still accept the old subkey for a grace period (to allow packet losses and reordering but reject replay attacks).

The main idea is that both peers maintain a subkey id that is incremented on every subkey rotation and is used to derive the subkey from the master key. This way, no subkeys will ever be exchanged between the peers and both peers can calculate all possible subkeys if they know the key id.
The current subkey id is attached to every encrypted message so that the receiver knows which subkey to use. There is a simple logic based on a current subkey id:
- If the key id is more than N (e.g. 5) key ids behind the current subkey id, drop the message (this is interpreted as a replay attack)
- If the key id equals the current subkey id, decrypt and process it
- If the key id is higher than the current subkey id, try to decrypt the message. If it succeeds, set the current subkey id to the received key id and process the message, else drop the message.
The current subkey id is used to limit the accepted subkey ids and reject replay attacks. Also this current subkey id is used to encrypt messages when sending them to the peer.

In a message, only the least significant 2 bytes of the subkey id are embedded in the message and the rest of the id is taken from the current subkey id (making sure to select add or subtract 1 from the upper bytes if the resulting subkey id is closer to the current one).

The key rotation happens on the following conditions:
* The last key rotation was over X (5) minutes ago
* A huge amount of messages have been sent using that subkey (see below)

On the key rotation, the sender increments its current subkey id and uses it to send future messages.
Both the sender and the receiver will issue subkey rotations, so every X minutes 2 rotations happen.
So the accepted subkey ids cover a time of X * N / 2 minutes. After that time a subkey can become known without harming the confidentiality.

Subkeys are derived from the master key by encryption a fixed dummy message with the master key and the subkey id as nonce.


## Nonces

Since both peers use the same subkey for encryption, they have to make sure to not use the same nonces. In order to guarantee that, the nonce space of 96 bits is split in two halves. The lower half belongs to the node with the smaller node_id and the upper half belongs to the node with the greater node_id (if the node_ids are identical, no connection is established).

Both peers start with a randomized nonce. The most significant 8 bits are fixed (0x00 or 0x80 depending on node_id) and the lower 11 bytes are randomized.
Whenever the upper byte reaches 0x40 or 0xc0, an extra subkey rotation is performed.

In order to reject replay attacks before the subkeys are invalidated by rotation, the nonces are invalidated too.
Both nodes track the highest seen nonce sent by the remote end. Once every T seconds that value is stored into a buffer and the last value from the buffer is taken as a minimum nonce value that will be accepted. This will be done for all subkey ids that are still valid.
The result of this is that messages have at least T seconds to reach their destination, but after that time the nonces will not be accepted anymore to prevent replay attacks.