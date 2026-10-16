package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.util.NostrUtil;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.HDPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Orchestrates identity creation, realm building, and attach/detach lifecycle.
 *
 * <p>Wraps a passive {@link KeyMaster} (state holder) and drives the workflow:
 * create identity, build service handlers, create realms, and manage
 * connector lifecycle. No identity private key is ever exported from the vault.
 */
public class KeyMasterController {

    private static final Logger log = LoggerFactory.getLogger(KeyMasterController.class);
    private static final int H = 0x80000000;

    private final KeyMaster km;
    private final SecureRandom realmIds = new SecureRandom();
    private ApprovalHandler approvalHandler;
    private Consumer<NostrTransport.ConnectionState> connectionStateListener;
    private Function<AvatarDescriptor, RelayClient> relayClientFactory;

    /**
     * Create a controller wrapping a KeyMaster.
     *
     * @param km the KeyMaster state holder
     */
    public KeyMasterController(KeyMaster km) {
        this.km = km;
    }

    /**
     * Create an identity: store key metadata entries and return the identity's
     * Nostr pubkey. Does not build handlers or realm — that happens in
     * {@link #attach(AvatarDescriptor, String)}.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     * @param pgpName  user's name for OpenPGP user ID
     * @param pgpEmail user's email for OpenPGP user ID
     * @return identity pubkey (64-char hex)
     */
    public String createIdentity(String identity, String pgpName, String pgpEmail) {
        return createIdentity(identity, pgpName, pgpEmail, Instant.now().getEpochSecond());
    }

    public String createIdentity(String identity, String pgpName, String pgpEmail,
                                  long creationTime) {
        KeyVault vault = km.vault;
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        // Build HD paths
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );

        String[] roleNames = {"certification", "signing"};
        List<HDPath> gpgPaths = new ArrayList<>();
        for (int role = 0; role < roleNames.length; role++) {
            gpgPaths.add(HDPath.m(
                    new ChildNumber(44, true),
                    new ChildNumber(Protocol.OPENPGP.coinType(), true),
                    new ChildNumber(mangledIdentity, true),
                    new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
                    new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
            ));
        }

        HDPath nostrHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.NOSTR.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );

        HDPath mlsHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.MLS.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );

        // Store via whichever metadata store is available
        KeyMetaDataStore keyStore = km.keyMetaDataStore;
        KVMetaStore kvStore = km.kvMetaStore;

        if (keyStore != null) {
            // Desktop path — generic KeyEntry
            keyStore.addIdentity(identity);
            keyStore.addKey(new KeyEntry(sshHdPath, Map.of("comment", identity)));
            for (int role = 0; role < roleNames.length; role++) {
                keyStore.addKey(new KeyEntry(gpgPaths.get(role), Map.of(
                        "label", identity + " / " + roleNames[role],
                        "key_type", "ed25519",
                        "identity", identity,
                        "creation_time", String.valueOf(creationTime),
                        "pgp_name", pgpName,
                        "pgp_email", pgpEmail)));
            }
            keyStore.addKey(new KeyEntry(nostrHdPath, Map.of("identity", identity)));
            keyStore.addKey(new KeyEntry(mlsHdPath, Map.of("identity", identity)));
        } else if (kvStore != null) {
            // Android path — typed key entries
            kvStore.put(new SSHKeyEntry(sshHdPath, identity, identity));
            for (int role = 0; role < roleNames.length; role++) {
                kvStore.put(new GPGKeyEntry(gpgPaths.get(role), identity,
                        pgpName, pgpEmail, creationTime));
            }
            // Derive Nostr pubkey for the NostrKeyEntry
            int identityIndex = mangledIdentity | H;
            int[] nostrPath = {
                    44 | H,
                    Protocol.NOSTR.coinType() | H,
                    identityIndex,
                    new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                    new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
            };
            byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data();
            String pubkeyHex = NostrUtil.bytesToHex(Arrays.copyOfRange(compressed, 1, 33));
            kvStore.put(new NostrKeyEntry(nostrHdPath, identity, pubkeyHex));
        } else {
            throw new IllegalStateException("No metadata store available for createIdentity");
        }

        // Derive pubkey from vault (no private key export)
        int identityIndex = mangledIdentity | H;
        int[] nostrPath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                identityIndex,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
        byte[] compressedPub = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data();
        String pubkey = NostrUtil.bytesToHex(Arrays.copyOfRange(compressedPub, 1, 33));

        log.info("Identity created: {}", pubkey);
        return pubkey;
    }

    /**
     * Set an approval handler for incoming service requests.
     *
     * <p>Propagated to every live realm, which re-wires its handlers' approval
     * UI in place rather than rebuilding them.
     *
     * @param handler approval handler, or {@code null} to auto-approve
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
        km.realms.values().forEach(realm -> realm.setApprovalHandler(handler));
    }

    /**
     * Create a realm: an identity scope that can then be attached to one or
     * more avatars.
     *
     * <p>The realm id is 31 bits from {@link SecureRandom}, redrawn while the
     * value is already in use. It is random rather than a counter or a
     * timestamp because two realms created in the same millisecond would
     * otherwise share a realm key, and a clock stepped backwards could revive
     * a dead realm's keys.
     *
     * @param name            user-facing name; when blank, the primary
     *                        identity's local part is used, with a numeric
     *                        suffix on collision
     * @param primaryIdentity the primary identity, whose Nostr key signs the
     *                        handshake; must appear in {@code selections}
     * @param selections      what the realm serves, one row per identity
     * @return the new realm
     */
    public Realm createRealm(String name, Identity primaryIdentity,
                             List<IdentitySelection> selections) {
        int realmId = nextRealmId();
        String realmName = (name == null || name.isBlank())
                ? uniqueDefaultName(primaryIdentity)
                : name;

        Realm realm = new Realm(realmId, realmName, selections, primaryIdentity,
                km.vault, availableKeys(), approvalHandler);
        if (connectionStateListener != null) {
            realm.setConnectionStateListener(connectionStateListener);
        }
        if (relayClientFactory != null) {
            realm.setRelayClientFactory(relayClientFactory);
        }
        km.realms.put(realmId, realm);
        log.info("Realm created: id={} name={} identities={}",
                realmId, realmName, realm.identityNames());
        return realm;
    }

    /** Create a realm serving all protocols of a single identity. */
    public Realm createRealm(String name, Identity primaryIdentity) {
        return createRealm(name, primaryIdentity,
                List.of(new IdentitySelection(primaryIdentity)));
    }

    /**
     * Add a connector to an existing realm — the "connect to an existing realm"
     * outcome of a QR scan.
     *
     * @param realmId    the realm to join
     * @param descriptor avatar descriptor from the scan
     * @return the connector id and the attach event id
     */
    public Realm.AttachResult attachToRealm(int realmId, AvatarDescriptor descriptor)
            throws Exception {
        Realm realm = requireRealm(realmId);
        return realm.attach(descriptor);
    }

    /**
     * Detach one connector. When this leaves its realm with no connectors, the
     * realm is removed; emptiness alone is not the trigger, so a realm created
     * but not yet attached survives.
     */
    public void detach(int realmId, int connectorId) throws Exception {
        Realm realm = km.realms.get(realmId);
        if (realm == null) {
            log.warn("No realm {} to detach from", realmId);
            return;
        }
        realm.detach(connectorId);
        if (!realm.hasConnectors()) {
            km.realms.remove(realmId);
            log.info("Realm {} removed — last connector detached", realmId);
        }
    }

    /** Detach every connector of a realm and remove the realm. */
    public void detachRealm(int realmId) {
        Realm realm = km.realms.remove(realmId);
        if (realm == null) {
            log.warn("No realm {} to detach", realmId);
            return;
        }
        realm.detachAll();
        log.info("Realm {} detached and removed", realmId);
    }

    /** Detach every realm. */
    public void detachAll() {
        for (int realmId : Set.copyOf(km.realms.keySet())) {
            detachRealm(realmId);
        }
    }

    /** Live realms, keyed by realm id. */
    public Map<Integer, Realm> realms() {
        return Map.copyOf(km.realms);
    }

    /** A live realm, or {@code null}. */
    public Realm getRealm(int realmId) {
        return km.realms.get(realmId);
    }

    /**
     * Attach to an avatar with a single identity: creates a realm and its first
     * connector. Retained for single-session callers.
     *
     * @return the attach event id
     */
    public String attach(AvatarDescriptor avatar, String identity) throws Exception {
        return attach(avatar, identity, List.of());
    }

    /**
     * Attach to an avatar with a primary identity and additional identities,
     * all serving every protocol: creates a realm and its first connector.
     *
     * <p>Replaces the former predicate-based overload. Key selection is data
     * now, so the caller passes identities rather than lambdas — which is also
     * what makes a multi-identity realm expressible over JSON-RPC.
     *
     * @return the attach event id
     */
    public String attach(AvatarDescriptor avatar, String identity,
                         List<String> additionalIdentities) throws Exception {
        Identity primary = new Identity(identity);
        List<IdentitySelection> selections = new ArrayList<>();
        selections.add(new IdentitySelection(primary));
        if (additionalIdentities != null) {
            for (String extra : additionalIdentities) {
                if (extra != null && !extra.isBlank() && !extra.equals(identity)) {
                    selections.add(new IdentitySelection(new Identity(extra)));
                }
            }
        }

        Realm realm = createRealm(null, primary, selections);
        try {
            return realm.attach(avatar).attachEventId();
        } catch (Exception e) {
            km.realms.remove(realm.id());
            throw e;
        }
    }

    /**
     * Detach every realm. Retained for single-session callers.
     */
    public void detach() {
        if (km.realms.isEmpty()) {
            log.warn("No active session to detach");
            return;
        }
        detachAll();
    }

    /** Every key the metadata store holds, from whichever store is configured. */
    private List<KeyEntry> availableKeys() {
        if (km.keyMetaDataStore != null) {
            return km.keyMetaDataStore.allKeys();
        }
        if (km.kvMetaStore != null) {
            return km.kvMetaStore.all().stream()
                    .map(AbstractKeyEntry::toKeyEntry)
                    .collect(Collectors.toList());
        }
        throw new IllegalStateException("Metadata store is required to build a realm");
    }

    private Realm requireRealm(int realmId) {
        Realm realm = km.realms.get(realmId);
        if (realm == null) {
            throw new IllegalArgumentException("No such realm: " + realmId);
        }
        return realm;
    }

    private int nextRealmId() {
        int realmId;
        do {
            realmId = realmIds.nextInt() & 0x7FFFFFFF;
        } while (km.realms.containsKey(realmId));
        return realmId;
    }

    private String uniqueDefaultName(Identity primaryIdentity) {
        String base = primaryIdentity.localPart();
        String candidate = base;
        int suffix = 1;
        while (nameTaken(candidate)) {
            suffix++;
            candidate = base + "-" + suffix;
        }
        return candidate;
    }

    private boolean nameTaken(String candidate) {
        return km.realms.values().stream().anyMatch(r -> candidate.equals(r.name()));
    }

    /**
     * Set a listener for relay connection state changes (CONNECTED, RETRYING,
     * DISCONNECTED).  Propagated to the connector/transport on attach.
     *
     * @param listener state consumer, or {@code null} to clear
     */
    public void setConnectionStateListener(Consumer<NostrTransport.ConnectionState> listener) {
        this.connectionStateListener = listener;
        km.realms.values().forEach(realm -> realm.setConnectionStateListener(listener));
    }

    /**
     * Set a connection state listener for one realm only. This is what a
     * per-realm UI state needs; the propagate-to-all variant above remains for
     * single-realm callers.
     *
     * @param realmId  the realm to listen to
     * @param listener state consumer, or {@code null} to clear
     */
    public void setConnectionStateListener(int realmId,
                                           Consumer<NostrTransport.ConnectionState> listener) {
        requireRealm(realmId).setConnectionStateListener(listener);
    }

    /**
     * Set a factory for creating relay clients. When set, the connector uses it
     * instead of defaulting to {@link NostrRelayClient}. This allows the Android
     * layer to inject an {@code RfcommRelayClient} when the descriptor has a BT address.
     */
    public void setRelayClientFactory(Function<AvatarDescriptor, RelayClient> factory) {
        this.relayClientFactory = factory;
        km.realms.values().forEach(realm -> realm.setRelayClientFactory(factory));
    }

    /**
     * Restore an identity in the metadata store without creating keys.
     * Used when restoring from a QR-scanned backup.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     */
    public void restoreIdentity(String identity) {
        KeyMetaDataStore keyStore = km.keyMetaDataStore;
        if (keyStore == null) {
            throw new IllegalStateException("Metadata store is required for restoreIdentity");
        }
        keyStore.addIdentity(identity);
        log.info("Identity restored: {}", identity);
    }

    /**
     * Restore GPG key metadata entries (certification + signing) for an identity.
     * Used when restoring from a QR-scanned backup with known creation time.
     *
     * @param identity     identity identifier
     * @param pgpName      user's name for OpenPGP user ID
     * @param pgpEmail     user's email for OpenPGP user ID
     * @param creationTime key creation time (epoch seconds)
     */
    public void restoreGpgKeys(String identity, String pgpName, String pgpEmail, long creationTime) {
        KeyMetaDataStore keyStore = km.keyMetaDataStore;
        if (keyStore == null) {
            throw new IllegalStateException("Metadata store is required for restoreGpgKeys");
        }
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        String[] roleNames = {"certification", "signing"};
        for (int role = 0; role < roleNames.length; role++) {
            HDPath gpgHdPath = HDPath.m(
                    new ChildNumber(44, true),
                    new ChildNumber(Protocol.OPENPGP.coinType(), true),
                    new ChildNumber(mangledIdentity, true),
                    new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
                    new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
            );
            keyStore.addKey(new KeyEntry(gpgHdPath, Map.of(
                    "label", identity + " / " + roleNames[role],
                    "key_type", "ed25519",
                    "identity", identity,
                    "creation_time", String.valueOf(creationTime),
                    "pgp_name", pgpName,
                    "pgp_email", pgpEmail)));
        }
        log.info("GPG keys restored for identity: {}", identity);
    }

    /**
     * Returns the wrapped KeyMaster for read-only state access.
     */
    public KeyMaster getKeyMaster() {
        return km;
    }
}
