package club.dwdc.keymaster;

/**
 * Signs, encrypts, and performs key agreement for the transport layer
 * using a vault-backed device key.
 *
 * <p>Extends {@link NostrIdentitySigner} (pubkey + sign) with ECDH
 * key agreement needed for NIP-44 encrypt/decrypt at the transport level.
 */
public interface TransportSigner extends NostrIdentitySigner {

    /**
     * ECDH key agreement — returns the 32-byte shared x-coordinate
     * (secp256k1 point multiplication with the peer's public key).
     *
     * @param peerPubKey 32-byte x-only public key of the peer
     * @return 32-byte shared secret (x-coordinate)
     */
    byte[] ecdh(byte[] peerPubKey);
}
