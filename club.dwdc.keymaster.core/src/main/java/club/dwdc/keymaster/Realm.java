package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Realm — a named identity scope that owns its avatar connections.
 *
 * <p>A realm is defined by its {@link IdentitySelection}s: which identities it
 * serves and, per identity, which protocols. The constructor resolves that
 * definition once — into one service handler per service, each holding the vault
 * paths it may use — and the realm is immutable thereafter. Changing what a realm
 * serves would change which service avatars the avatar spawned and which channel
 * keys both sides derived at attach, so it requires a new realm and a fresh
 * attach rather than an in-place edit.
 *
 * <p>Handlers are shared by every connector in the realm: {@link ServiceChannel}
 * resolves them lazily through the realm, so joining a second avatar needs no
 * handler duplication. Approval policy and handler-held caches are therefore
 * realm-wide.
 *
 * <p>The {@code id} is immutable and is the only input to realm key derivation;
 * the {@code name} is user-facing and purely local, so renaming never re-keys
 * anything and never reaches an avatar. See {@code doc/key-derivation.md} for
 * the paths and {@code doc/keymaster-component-architecture.md} for the
 * ownership rules.
 */
public class Realm {

    private static final Logger log = LoggerFactory.getLogger(Realm.class);

    private static final int H = 0x80000000;

    /** BIP-43 purpose for the KM-internal tree: {@code mangle("keymaster")}. */
    static final int KM_PURPOSE = Bip32KeyDerivator.mangle("keymaster");

    /** Scheme version of the KM-internal layout. */
    static final int KM_SCHEME = 1;

    // ── definition: fixed at construction ─────────────────────────────────

    private final int id;
    private volatile String name;
    private final Identity primaryIdentity;
    private final Map<Integer, Identity> identities;

    // ── resolved once, in the constructor ─────────────────────────────────

    private final Map<Integer, AbstractServiceHandler> handlers;
    private final int[] primaryNostrPath;

    private final KeyVault vault;
    private volatile ApprovalHandler approvalHandler;

    // ── runtime ───────────────────────────────────────────────────────────

    /**
     * Keyed by connector id = {@code mangle(avatar login xpub)}: unique within
     * the realm, stable across reconnects, and already the derivation index.
     */
    private final Map<Integer, NipxxConnector> connectors = new ConcurrentHashMap<>();

    private volatile Consumer<NostrTransport.ConnectionState> connectionStateListener;
    private volatile Function<AvatarDescriptor, RelayClient> relayClientFactory;

    /**
     * Resolve a realm from its definition.
     *
     * @param id               31 random bits from a CSPRNG, drawn by the controller
     * @param name             user-facing display name
     * @param selections       what this realm serves; non-empty. Construction
     *                         input only — not retained
     * @param primaryIdentity  the primary identity, whose Nostr key signs the
     *                         handshake; must be among {@code selections}
     * @param vault            vault for all cryptographic operations
     * @param availableKeys    every key the selections may draw from, already
     *                         materialised from whichever metadata store the
     *                         caller holds
     * @param approvalHandler  approval handler, or {@code null}
     */
    public Realm(int id, String name, List<IdentitySelection> selections,
                 Identity primaryIdentity, KeyVault vault,
                 List<KeyEntry> availableKeys, ApprovalHandler approvalHandler) {

        if (selections == null || selections.isEmpty()) {
            throw new IllegalArgumentException("realm needs at least one identity selection");
        }
        if (primaryIdentity == null) {
            throw new IllegalArgumentException("realm needs a primary identity");
        }
        if (vault == null) {
            throw new IllegalArgumentException("realm needs a vault");
        }

        // Build the mangled -> identity map, rejecting a collision: every
        // predicate matches on the mangled value alone, so two identities
        // sharing one would merge their scopes and silently void each other's
        // protocol filters.
        Map<Integer, Identity> byMangled = new HashMap<>();
        for (IdentitySelection selection : selections) {
            Identity identity = selection.identity();
            Identity previous = byMangled.putIfAbsent(identity.mangled(), identity);
            if (previous != null && !previous.equals(identity)) {
                throw new IllegalArgumentException("mangle collision in realm " + id
                        + ": " + previous.name() + " and " + identity.name()
                        + " share path index " + identity.mangled());
            }
        }
        if (!byMangled.containsValue(primaryIdentity)) {
            throw new IllegalArgumentException("primary identity " + primaryIdentity.name()
                    + " is not among the realm's selections");
        }
        this.identities = Map.copyOf(byMangled);

        this.id = id;
        this.primaryIdentity = primaryIdentity;
        this.name = (name == null || name.isBlank()) ? primaryIdentity.localPart() : name;
        this.vault = vault;
        this.approvalHandler = approvalHandler;

        this.primaryNostrPath = new int[]{
                44 | H,
                Protocol.NOSTR.coinType() | H,
                primaryIdentity.mangled() | H,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };

        this.handlers = buildHandlers(availableKeys, selections);
    }

    /**
     * Direct-registration realm: nothing is resolved from a store, and handlers
     * are registered with {@link #putHandler}. For callers that build their own
     * handlers, and for tests that exercise channel dispatch.
     */
    Realm(int id, String name, Identity primaryIdentity, KeyVault vault) {
        this(id, name, List.of(new IdentitySelection(primaryIdentity)),
                primaryIdentity, vault, List.of(), null);
    }

    public int id() {
        return id;
    }

    public String name() {
        return name;
    }

    /** Rename the realm. Never re-keys anything: derivation uses {@link #id()}. */
    public void setName(String name) {
        this.name = name;
    }

    /** The primary identity — its Nostr key signs the handshake. */
    public Identity primaryIdentity() {
        return primaryIdentity;
    }

    /** The identities this realm serves, in no particular order. */
    public Collection<Identity> identities() {
        return identities.values();
    }

    /** Clear-text identity names, for the UI, the notification and logs. */
    public List<String> identityNames() {
        return identities.values().stream().map(Identity::name).sorted().toList();
    }

    /**
     * Reverse lookup: which identity a key's level-3 path component belongs to,
     * scoped to this realm. A miss means the realm does not serve that identity.
     *
     * @param mangled level-3 path component, without the hardened bit
     */
    public Optional<Identity> identityFor(int mangled) {
        return Optional.ofNullable(identities.get(mangled));
    }

    /** Path of the primary identity's Nostr key — the handshake key. */
    int[] primaryNostrPath() {
        return primaryNostrPath.clone();
    }

    // ── handlers ──────────────────────────────────────────────────────────

    /**
     * Resolve the selections into one handler per service, each holding the
     * {@link KeyEntry} paths it may use. Runs once, from the constructor.
     *
     * <p>Handlers are keyed by service rather than by coin type: the Nostr
     * service owns both the Nostr and the MLS keys, so an MLS path is resolved
     * here rather than rebuilt per request.
     */
    private Map<Integer, AbstractServiceHandler> buildHandlers(
            List<KeyEntry> availableKeys, List<IdentitySelection> selections) {

        Map<Integer, AbstractServiceHandler> built = new ConcurrentHashMap<>();
        if (availableKeys == null || availableKeys.isEmpty()) {
            log.debug("Realm {} ({}): no keys available — handlers must be registered directly",
                    id, name);
            return built;
        }

        Predicate<KeyEntry> combined = selections.stream()
                .map(IdentitySelection::toPredicate)
                .reduce(k -> false, Predicate::or);

        Map<Integer, List<KeyEntry>> byCoinType = new HashMap<>();
        for (KeyEntry entry : availableKeys) {
            if (combined.test(entry)) {
                byCoinType.computeIfAbsent(entry.coinType(), c -> new ArrayList<>()).add(entry);
            }
        }

        register(built, Protocol.SSH.coinType(),
                new SshServiceHandler(vault, keysOf(byCoinType, Protocol.SSH)));
        register(built, Protocol.OPENPGP.coinType(),
                new GpgServiceHandler(vault, keysOf(byCoinType, Protocol.OPENPGP)));
        register(built, Protocol.NOSTR.coinType(),
                new NostrServiceHandler(vault, keysOf(byCoinType, Protocol.NOSTR),
                        keysOf(byCoinType, Protocol.MLS)));

        log.info("Realm {} ({}) resolved {} handler(s) for {}",
                id, name, built.size(), identityNames());
        return built;
    }

    /** Registers a handler only if it has at least one path to serve. */
    private void register(Map<Integer, AbstractServiceHandler> into, int coinType,
                          AbstractServiceHandler handler) {
        if (handler.keys().isEmpty()) {
            return;
        }
        applyApprovalUI(coinType, handler);
        into.put(coinType, handler);
    }

    private static List<KeyEntry> keysOf(Map<Integer, List<KeyEntry>> byCoinType, Protocol protocol) {
        return byCoinType.getOrDefault(protocol.coinType(), List.of());
    }

    /**
     * Get the handler for the given coin type.
     *
     * @return the handler, or {@code null} if none is registered
     */
    public AbstractServiceHandler getHandler(int coinType) {
        return handlers.get(coinType);
    }

    /**
     * Register or replace a handler. Used by callers that build handlers
     * themselves instead of resolving them from a metadata store.
     */
    public void putHandler(int coinType, AbstractServiceHandler handler) {
        applyApprovalUI(coinType, handler);
        handlers.put(coinType, handler);
    }

    /** Coin types with a registered handler. */
    public Set<Integer> getHandlerCoinTypes() {
        return Set.copyOf(handlers.keySet());
    }

    /**
     * Re-wire the approval UI on the existing handlers.
     *
     * <p>Deliberately does not re-resolve: the key tables are fixed, and
     * rebuilding handlers would discard their policy overrides and MLS caches
     * under every live connector.
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
        handlers.forEach(this::applyApprovalUI);
    }

    private void applyApprovalUI(int coinType, AbstractServiceHandler handler) {
        String serviceType = serviceTypeOf(coinType);
        handler.setApprovalUI(approvalHandler == null || serviceType == null
                ? null
                : new ApprovalHandlerAdapter(approvalHandler, serviceType));
    }

    static String serviceTypeOf(int coinType) {
        if (coinType == Protocol.SSH.coinType()) return "ssh";
        if (coinType == Protocol.OPENPGP.coinType()) return "gpg";
        if (coinType == Protocol.NOSTR.coinType()) return "nostr";
        return null;
    }

    // ── connectors ────────────────────────────────────────────────────────

    /**
     * The outcome of an attach.
     *
     * @param connectorId   {@code mangle(avatar login xpub)} — the id {@link #detach} takes
     * @param attachEventId the attach event id, which callers store as a session id
     */
    public record AttachResult(int connectorId, String attachEventId) {}

    /**
     * Add a connector to this realm: resolve its connection key path from
     * {@code (realm id, avatar login xpub)}, connect, and return its id.
     *
     * <p>Path: {@code m/KM_PURPOSE'/KM_SCHEME'/id'/mangle(loginXpub)'}, all four
     * levels hardened. The avatar derives service channels below the exported
     * xpub at {@code protocol_index/seq}, so nothing above it is visible to it.
     * This is the one path that cannot be resolved in the constructor, since it
     * depends on the avatar; it is resolved once here and stored by the connector.
     *
     * @throws IllegalStateException if this realm already has a connector for
     *                               that avatar — two connectors sharing a
     *                               connector index would share channel keys
     */
    public AttachResult attach(AvatarDescriptor avatar) throws Exception {
        if (avatar == null || avatar.loginXpub() == null) {
            throw new IllegalArgumentException("attach needs a descriptor with a login xpub");
        }
        int connectorId = Bip32KeyDerivator.mangle(avatar.loginXpub());

        NipxxConnector connector = new NipxxConnector(this);
        if (connectors.putIfAbsent(connectorId, connector) != null) {
            throw new IllegalStateException("realm " + id
                    + " already has a connector for this avatar (index " + connectorId + ")");
        }

        try {
            int[] connectorPath = connectorPath(id, avatar.loginXpub());

            VaultResult connectorKey = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, connectorPath);
            if (!connectorKey.isOk()) {
                throw new IllegalStateException(
                        "connector key derivation failed: status=" + connectorKey.status());
            }
            String realmXpub = HDKeyDerivation
                    .createMasterPubKeyFromBytes(connectorKey.data(), connectorKey.chainCode())
                    .serializePubB58(BitcoinNetwork.MAINNET);

            connector.setRealmVault(vault, connectorPath, realmXpub);
            if (connectionStateListener != null) {
                connector.setConnectionStateListener(connectionStateListener);
            }
            if (relayClientFactory != null) {
                connector.setRelayClientFactory(relayClientFactory);
            }

            String attachEventId = connector.connect(avatar,
                    new VaultTransportSigner(vault, primaryNostrPath));
            log.info("Realm {} ({}) attached connector {}", id, name, connectorId);
            return new AttachResult(connectorId, attachEventId);
        } catch (Exception e) {
            connectors.remove(connectorId);
            throw e;
        }
    }

    /**
     * The connection key path for one avatar link:
     * {@code m/mangle("keymaster")'/scheme'/realmId'/mangle(login_xpub)'}.
     * All four levels hardened; nothing above the exported xpub is visible to
     * the avatar. See {@code doc/key-derivation.md}.
     */
    static int[] connectorPath(int realmId, String avatarLoginXpub) {
        return new int[]{
                KM_PURPOSE | H,
                KM_SCHEME | H,
                realmId | H,
                Bip32KeyDerivator.mangle(avatarLoginXpub) | H
        };
    }

    /** Close one connector. */
    public void detach(int connectorId) throws Exception {
        NipxxConnector connector = connectors.remove(connectorId);
        if (connector == null) {
            log.warn("Realm {}: no connector {}", id, connectorId);
            return;
        }
        connector.disconnect();
        log.info("Realm {} ({}) detached connector {}", id, name, connectorId);
    }

    /** Close every connector. The realm itself is removed by the controller. */
    public void detachAll() {
        for (int connectorId : Set.copyOf(connectors.keySet())) {
            try {
                detach(connectorId);
            } catch (Exception e) {
                log.error("Realm {}: detach of connector {} failed", id, connectorId, e);
            }
        }
    }

    /** Ids of the live connectors. */
    public Set<Integer> connectorIds() {
        return Set.copyOf(connectors.keySet());
    }

    /** Whether this realm has at least one live connector. */
    public boolean hasConnectors() {
        return !connectors.isEmpty();
    }

    /** Set the relay connection state listener for this realm's connectors. */
    public void setConnectionStateListener(Consumer<NostrTransport.ConnectionState> listener) {
        this.connectionStateListener = listener;
        connectors.values().forEach(c -> c.setConnectionStateListener(listener));
    }

    /** Set the relay client factory used by connectors created from now on. */
    public void setRelayClientFactory(Function<AvatarDescriptor, RelayClient> factory) {
        this.relayClientFactory = factory;
    }
}
