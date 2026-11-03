package club.dwdc.keymaster;

/**
 * One X.509 key as {@code x509.list} returns it.
 *
 * @param label     {@link IdentityPaths#x509Label}, the PKCS#11 {@code CKA_LABEL}
 * @param path      {@link IdentityPaths#pathString} — the value {@code x509.sign} takes
 * @param publicKey 65-byte SEC1 uncompressed P-256 point ({@code 04 || X || Y})
 * @param id        SHA-256 of the DER SubjectPublicKeyInfo, as
 *                  {@link X509CertCheck} builds it; the PKCS#11 {@code CKA_ID}
 * @param cert      stored certificate DER, or {@code null} — then the field is
 *                  absent on the wire
 */
public record X509Key(String label, String path, byte[] publicKey, byte[] id, byte[] cert) {
}
