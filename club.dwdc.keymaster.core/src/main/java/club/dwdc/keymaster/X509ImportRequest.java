package club.dwdc.keymaster;

import java.util.List;

/**
 * An {@code x509.import} request.
 *
 * @param der   the certificate, DER
 * @param chain reserved for the issuing chain. Not stored yet (mission 50):
 *              a request that carries one is refused with
 *              {@code "unsupported"}, so no client believes a chain was kept.
 */
public record X509ImportRequest(byte[] der, List<byte[]> chain) {

    /** A request with the certificate only. */
    public X509ImportRequest(byte[] der) {
        this(der, null);
    }
}
