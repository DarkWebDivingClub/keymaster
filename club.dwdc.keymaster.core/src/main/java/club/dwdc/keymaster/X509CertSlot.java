package club.dwdc.keymaster;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The certificate slot of an X.509 key entry: metadata key
 * {@value #KEY}, value the certificate's DER, base64-encoded.
 *
 * <p>No store interface change — {@link KeyEntry#metadata()} already holds
 * strings, so this works with every {@link KeyMetaDataStore}. Nothing fills
 * the slot yet.
 */
public final class X509CertSlot {

    /** Metadata key holding the base64 DER certificate. */
    public static final String KEY = "x509_cert";

    private X509CertSlot() {
    }

    /** The stored certificate DER, or empty if the entry has none. */
    public static Optional<byte[]> get(KeyEntry entry) {
        String value = entry.metadata() == null ? null : entry.metadata().get(KEY);
        return value == null ? Optional.empty() : Optional.of(Base64.getDecoder().decode(value));
    }

    /** A copy of the entry, same path and metadata, with the certificate set. */
    public static KeyEntry with(KeyEntry entry, byte[] der) {
        Map<String, String> metadata = new HashMap<>();
        if (entry.metadata() != null) {
            metadata.putAll(entry.metadata());
        }
        metadata.put(KEY, Base64.getEncoder().encodeToString(der));
        return new KeyEntry(entry.path(), Map.copyOf(metadata));
    }
}
