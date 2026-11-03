package club.dwdc.keymaster;

/**
 * An {@code x509.sign} request.
 *
 * @param path   exactly an {@link X509Key#path()} from {@code x509.list}
 * @param digest the 32-byte digest to sign; the caller hashes
 */
public record X509SignRequest(String path, byte[] digest) {
}
