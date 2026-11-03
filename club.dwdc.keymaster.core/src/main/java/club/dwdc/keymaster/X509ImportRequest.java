package club.dwdc.keymaster;

/**
 * An {@code x509.import} request.
 *
 * @param der the certificate, DER
 */
public record X509ImportRequest(byte[] der) {
}
