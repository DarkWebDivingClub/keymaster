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
import java.util.function.BiConsumer;
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

    /** Serializes realm id and default-name allocation; see createRealm. */
    private final Object realmAllocation = new Object();
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

        Identity id = new Identity(identity);
        HDPath sshHdPath = IdentityPaths.hdPath(IdentityPaths.ssh(id));

        String[] roleNames = {"certification", "signing"};
        List<HDPath> gpgPaths = new ArrayList<>();
        for (int role = 0; role < roleNames.length; role++) {
            gpgPaths.add(IdentityPaths.hdPath(IdentityPaths.gpg(id, role)));
        }

        HDPath nostrHdPath = IdentityPaths.hdPath(IdentityPaths.nostr(id));
        HDPath mlsHdPath = IdentityPaths.hdPath(IdentityPaths.mlsSign(id));

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
            int[] nostrPath = IdentityPaths.nostr(id);
            byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data();
            String pubkeyHex = NostrUtil.bytesToHex(Arrays.copyOfRange(compressed, 1, 33));
            kvStore.put(new NostrKeyEntry(nostrHdPath, identity, pubkeyHex));
        } else {
            throw new IllegalStateException("No metadata store available for createIdentity");
        }

        // Derive pubkey from vault (no private key export)
        int[] nostrPath = IdentityPaths.nostr(id);
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
     * The approval handler in force, or {@code null} if every request is
     * auto-approved.
     *
     * @return the current handler
     */
    public ApprovalHandler approvalHandler() {
        return approvalHandler;
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
        Realm realm;
        // Both the id and the default name are chosen by looking at the realms
        // that exist, so choosing and registering has to be one step: two
        // concurrent creates would otherwise pass the same check and the
        // second would either take the first's name or, far less likely but
        // far worse, its id — replacing a live realm in the map. Removal needs
        // no lock, since it only ever frees an id or a name.
        synchronized (realmAllocation) {
            int realmId = nextRealmId();
            String realmName = (name == null || name.isBlank())
                    ? uniqueDefaultName(primaryIdentity)
                    : name;

            realm = new Realm(realmId, realmName, selections, primaryIdentity,
                    km.vault, availableKeys(), approvalHandler);
            if (connectionStateListener != null) {
                realm.setConnectionStateListener(connectionStateListener);
            }
            if (relayClientFactory != null) {
                realm.setRelayClientFactory(relayClientFactory);
            }
            km.realms.put(realmId, realm);
        }
        log.info("Realm created: id={} name={} identities={}",
                realm.id(), realm.name(), realm.identityNames());
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
        Realm.AttachResult result = realm.attach(descriptor);

        // A concurrent detach can remove the realm between the lookup above and
        // the attach completing, which would leave a live connector on a realm
        // nothing can reach. Detect it and undo rather than leak.
        if (km.realms.get(realmId) != realm) {
            log.warn("Realm {} was removed while attaching; undoing connector {}",
                    realmId, result.connectorId());
            realm.detach(result.connectorId());
            throw new IllegalStateException("realm " + realmId + " was detached while attaching");
        }
        return result;
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
     * Set a listener for one realm that is told which connector changed state.
     *
     * <p>What a multi-avatar UI needs: with two connectors on one realm, the
     * realm-wide listener above fires for both and cannot distinguish them, so
     * a row per avatar cannot show its own dot. The id is the one
     * {@link Realm.AttachResult#connectorId()} returned.
     *
     * @param realmId  the realm to listen to
     * @param listener receives (connector id, state), or {@code null} to clear
     */
    public void setConnectorStateListener(int realmId,
            BiConsumer<Integer, NostrTransport.ConnectionState> listener) {
        requireRealm(realmId).setConnectorStateListener(listener);
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
     * Returns the wrapped KeyMaster for read-only state access.
     */
    public KeyMaster getKeyMaster() {
        return km;
    }
}
