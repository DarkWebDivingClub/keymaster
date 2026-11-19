package club.dwdc.keymaster;

import java.util.List;

/**
 * Result of {@code x509.list}: wire {@code {"keys":[...]}}.
 */
public record X509ListResponse(List<X509Key> keys) {
}
