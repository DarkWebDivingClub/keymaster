package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Optional;

/**
 * Where {@link X509ServiceHandler} keeps certificates: one per key path, a new
 * one replacing the old.
 *
 * <p>Two implementations, one per metadata store: {@link KVX509CertStore}
 * (the typed store, Android) keeps an {@link X509KeyEntry};
 * {@link KeyMetaDataX509CertStore} (desktop) keeps the {@link X509CertSlot}
 * in a generic {@link KeyEntry}. Mission 50.
 */
public interface X509CertStore {

    /** The certificate DER stored for {@code path}, or empty. */
    Optional<byte[]> certificate(HDPath path);

    /**
     * Store {@code der} for {@code path}, replacing any earlier certificate and
     * keeping the entry's other metadata.
     *
     * @param identity the identity name, used when the entry does not exist yet
     */
    void putCertificate(HDPath path, String identity, byte[] der);

    /** A certificate store over the typed store, or {@code null} for {@code null}. */
    static X509CertStore of(KVMetaStore store) {
        return store == null ? null : new KVX509CertStore(store);
    }

    /** A certificate store over the generic store, or {@code null} for {@code null}. */
    static X509CertStore of(KeyMetaDataStore store) {
        return store == null ? null : new KeyMetaDataX509CertStore(store);
    }
}
