package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.List;

/**
 * Storage for key metadata entries and identity name reverse lookups.
 */
public interface KeyMetaDataStore {

    void addIdentity(String identity);
    String getIdentityName(int mangleHash);

    void addKey(KeyEntry entry);
    void removeKey(HDPath path);
    KeyEntry getKey(HDPath path);
    List<KeyEntry> keysByProtocol(int coinType);
    List<KeyEntry> keysByIdentity(int mangleHash);
    List<KeyEntry> allKeys();
}
