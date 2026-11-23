package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Optional;

/**
 * {@link X509CertStore} over the typed {@link KVMetaStore}: the certificate
 * lives in the key's {@link X509KeyEntry}. Read on every call, no cache.
 */
public final class KVX509CertStore implements X509CertStore {

    private final KVMetaStore store;

    public KVX509CertStore(KVMetaStore store) {
        if (store == null) {
            throw new IllegalArgumentException("store must not be null");
        }
        this.store = store;
    }

    @Override
    public Optional<byte[]> certificate(HDPath path) {
        return store.get(path) instanceof X509KeyEntry entry ? entry.certificate() : Optional.empty();
    }

    /** An entry of another type at an X.509 path is replaced: the path says X.509. */
    @Override
    public void putCertificate(HDPath path, String identity, byte[] der) {
        X509KeyEntry base = store.get(path) instanceof X509KeyEntry entry
                ? entry
                : new X509KeyEntry(path, identity);
        store.put(base.withCertificate(der));
    }
}
