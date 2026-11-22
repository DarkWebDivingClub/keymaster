package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;
import java.util.Optional;

/**
 * {@link X509CertStore} over the generic {@link KeyMetaDataStore}: the
 * certificate is the entry's {@link X509CertSlot}. This is the 37.1.3
 * behaviour, unchanged. Read on every call, no cache.
 */
public final class KeyMetaDataX509CertStore implements X509CertStore {

    private final KeyMetaDataStore store;

    public KeyMetaDataX509CertStore(KeyMetaDataStore store) {
        if (store == null) {
            throw new IllegalArgumentException("store must not be null");
        }
        this.store = store;
    }

    @Override
    public Optional<byte[]> certificate(HDPath path) {
        KeyEntry entry = store.getKey(path);
        return entry == null ? Optional.empty() : X509CertSlot.get(entry);
    }

    @Override
    public void putCertificate(HDPath path, String identity, byte[] der) {
        KeyEntry base = store.getKey(path);
        if (base == null) {
            base = new KeyEntry(path, Map.of("identity", identity));
        }
        store.addKey(X509CertSlot.with(base, der));
    }
}
