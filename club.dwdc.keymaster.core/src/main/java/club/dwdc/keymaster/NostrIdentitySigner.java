package club.dwdc.keymaster;

/**
 * Signs data with the Nostr identity key (BIP-340 Schnorr).
 *
 * <p>Implementations back onto the vault's {@code FN_SIGN} function
 * so the private key never leaves the vault boundary.
 */
public interface NostrIdentitySigner {

    /**
     * The identity pubkey (64-char hex, x-only Schnorr).
     */
    String getPubkey();

    /**
     * Schnorr-sign a 32-byte hash with the identity key.
     *
     * @param hash 32-byte SHA-256 hash to sign
     * @return 64-byte Schnorr signature
     */
    byte[] sign(byte[] hash);
}
