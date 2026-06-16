package club.dwdc.keymaster;

import java.security.SecureRandom;

/**
 * Helper utilities for Nostr event handling.
 */
public class NostrEventHelper {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generate 32 bytes of auxiliary randomness for Schnorr signing (BIP-340).
     */
    public static byte[] generateAuxRand() {
        byte[] aux = new byte[32];
        SECURE_RANDOM.nextBytes(aux);
        return aux;
    }
}
