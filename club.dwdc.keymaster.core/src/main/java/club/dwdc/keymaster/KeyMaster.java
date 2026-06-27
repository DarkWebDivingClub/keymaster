package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KeyMaster — passive state holder for the DWDC Key System.
 *
 * <p>Holds the vault, key metadata store, realms, and connectors.
 * Orchestration (identity creation, realm building, attach/detach)
 * is handled by {@link KeyMasterController}.</p>
 */
public class KeyMaster {
    private static final Logger log = LoggerFactory.getLogger(KeyMaster.class);

    private final KeyVault vault;
    private final KeyMetaDataStore keyMetaDataStore;

    private final Map<String, Realm> realms = new ConcurrentHashMap<>();
    private final Map<String, Connector> connectors = new ConcurrentHashMap<>();

    /**
     * Create a KeyMaster from a ready-to-use KeyVault.
     *
     * @param vault KeyVault instance for cryptographic operations
     */
    public KeyMaster(KeyVault vault) {
        this(vault, (KeyMetaDataStore) null);
    }

    /**
     * Create a KeyMaster with an optional key metadata store.
     *
     * @param vault KeyVault instance for cryptographic operations
     * @param keyMetaDataStore metadata store, or {@code null}
     */
    public KeyMaster(KeyVault vault, KeyMetaDataStore keyMetaDataStore) {
        this.vault = vault;
        this.keyMetaDataStore = keyMetaDataStore;
    }

    /** The vault backing this KeyMaster. */
    public KeyVault getVault() {
        return vault;
    }

    /** The key metadata store, or {@code null} if none configured. */
    public KeyMetaDataStore getKeyMetaDataStore() {
        return keyMetaDataStore;
    }

    /** Store a realm under the given key. */
    public void putRealm(String key, Realm realm) {
        realms.put(key, realm);
    }

    /** Get the realm for the given key, or {@code null}. */
    public Realm getRealm(String key) {
        return realms.get(key);
    }

    /** Remove the realm for the given key. */
    public void removeRealm(String key) {
        realms.remove(key);
    }

    /** Store a connector under the given key. */
    public void putConnector(String key, Connector connector) {
        connectors.put(key, connector);
    }

    /** Get the connector for the given key, or {@code null}. */
    public Connector getConnector(String key) {
        return connectors.get(key);
    }

    /** Remove the connector for the given key. */
    public void removeConnector(String key) {
        connectors.remove(key);
    }
}
