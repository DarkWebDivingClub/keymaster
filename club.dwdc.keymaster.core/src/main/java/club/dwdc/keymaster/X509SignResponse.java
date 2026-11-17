package club.dwdc.keymaster;

/**
 * Result of {@code x509.sign}.
 *
 * @param signature 64-byte raw {@code r || s} (PKCS#11 {@code CKM_ECDSA} form)
 */
public record X509SignResponse(byte[] signature) {
}
