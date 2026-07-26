package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;

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

    public final KeyVault vault;
    public final KeyMetaDataStore keyMetaDataStore;
    public final KVMetaStore kvMetaStore;
    public final Map<String, Realm> realms = new ConcurrentHashMap<>();
    public final Map<String, Connector> connectors = new ConcurrentHashMap<>();

    /**
     * Create a KeyMaster from a ready-to-use KeyVault.
     *
     * @param vault KeyVault instance for cryptographic operations
     */
    public KeyMaster(KeyVault vault) {
        this(vault, (KeyMetaDataStore) null);
    }

    /**
     * Create a KeyMaster with a key metadata store (desktop path).
     *
     * @param vault KeyVault instance for cryptographic operations
     * @param keyMetaDataStore metadata store, or {@code null}
     */
    public KeyMaster(KeyVault vault, KeyMetaDataStore keyMetaDataStore) {
        this.vault = vault;
        this.keyMetaDataStore = keyMetaDataStore;
        this.kvMetaStore = null;
    }

    /**
     * Create a KeyMaster with a typed KV metadata store (Android path).
     *
     * @param vault KeyVault instance for cryptographic operations
     * @param kvMetaStore typed metadata store
     */
    public KeyMaster(KeyVault vault, KVMetaStore kvMetaStore) {
        this.vault = vault;
        this.keyMetaDataStore = null;
        this.kvMetaStore = kvMetaStore;
    }
}
