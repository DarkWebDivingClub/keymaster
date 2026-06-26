package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import org.bitcoinj.crypto.HDPath;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal in-memory {@link KeyMetaDataStore} for testing.
 *
 * <p>Same contract as {@link club.dwdc.keymaster.desktop.FileKeyMetaDataStore}
 * but without file persistence.
 */
class InMemoryKeyMetaDataStore implements KeyMetaDataStore {

    private final Map<HDPath, KeyEntry> keys = new LinkedHashMap<>();
    private final Map<Integer, String> identityNames = new LinkedHashMap<>();

    @Override
    public void addIdentity(String identity) {
        identityNames.put(Bip32KeyDerivator.mangle(identity), identity);
    }

    @Override
    public String getIdentityName(int mangleHash) {
        return identityNames.get(mangleHash);
    }

    @Override
    public void addKey(KeyEntry entry) {
        keys.put(entry.path(), entry);
    }

    @Override
    public void removeKey(HDPath path) {
        keys.remove(path);
    }

    @Override
    public KeyEntry getKey(HDPath path) {
        return keys.get(path);
    }

    @Override
    public List<KeyEntry> keysByProtocol(int coinType) {
        return keys.values().stream()
                .filter(e -> e.coinType() == coinType)
                .toList();
    }

    @Override
    public List<KeyEntry> keysByIdentity(int mangleHash) {
        return keys.values().stream()
                .filter(e -> e.identity() == mangleHash)
                .toList();
    }

    @Override
    public List<KeyEntry> allKeys() {
        return List.copyOf(keys.values());
    }
}
