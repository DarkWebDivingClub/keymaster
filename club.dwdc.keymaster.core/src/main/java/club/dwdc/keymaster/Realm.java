package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Realm — single source of truth for which service handlers are active.
 *
 * <p>Maintains a {@link ConcurrentHashMap} of handlers keyed by coin type.
 * Handlers can be populated either via {@link #resolveHandlers()} (filtering
 * keys from a {@link KeyMetaDataStore}) or manually via {@link #putHandler}.
 */
public class Realm {

    private final ConcurrentHashMap<Integer, AbstractServiceHandler> handlers = new ConcurrentHashMap<>();

    private List<Predicate<KeyEntry>> keySelections;
    private KeyMetaDataStore keyMetaDataStore;
    private KeyVault vault;
    private ApprovalHandler approvalHandler;

    /**
     * Full resolve path — resolves handlers from key selections against a metadata store.
     *
     * @param keySelections    predicates to select keys (combined with OR)
     * @param keyMetaDataStore store containing key entries and identity names
     * @param vault            vault for cryptographic operations
     * @param approvalHandler  approval handler for handlers, or {@code null}
     */
    public Realm(List<Predicate<KeyEntry>> keySelections,
                 KeyMetaDataStore keyMetaDataStore,
                 KeyVault vault, ApprovalHandler approvalHandler) {
        this.keySelections = keySelections;
        this.keyMetaDataStore = keyMetaDataStore;
        this.vault = vault;
        this.approvalHandler = approvalHandler;
        resolveHandlers();
    }

    /**
     * Manual path — creates an empty realm for populating via {@link #putHandler}.
     * Package-private; used by KeyMasterController for direct handler registration.
     */
    Realm() {
    }

    /**
     * Resolve handlers from the key metadata store using the configured key selections.
     *
     * <p>Combines all predicates with OR, filters the store's keys, groups by
     * coin type, and constructs the appropriate handler for each protocol.
     */
    public void resolveHandlers() {
        if (keySelections == null || keyMetaDataStore == null || vault == null) {
            return;
        }

        handlers.clear();

        Predicate<KeyEntry> combined = keySelections.stream()
                .reduce(k -> false, Predicate::or);

        Map<Integer, List<KeyEntry>> byProtocol = keyMetaDataStore.allKeys().stream()
                .filter(combined)
                .collect(Collectors.groupingBy(KeyEntry::coinType));

        for (var entry : byProtocol.entrySet()) {
            int coinType = entry.getKey();
            List<KeyEntry> keys = entry.getValue();

            if (coinType == Protocol.SSH.coinType()) {
                SshServiceHandler handler = new SshServiceHandler(vault, keys);
                if (approvalHandler != null) {
                    handler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "ssh"));
                }
                handlers.put(coinType, handler);
            } else if (coinType == Protocol.OPENPGP.coinType()) {
                GpgServiceHandler handler = new GpgServiceHandler(vault, keys);
                if (approvalHandler != null) {
                    handler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "gpg"));
                }
                handlers.put(coinType, handler);
            } else if (coinType == Protocol.NOSTR.coinType()) {
                NostrServiceHandler handler = new NostrServiceHandler(vault, keys);
                if (approvalHandler != null) {
                    handler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "nostr"));
                }
                handlers.put(coinType, handler);
            }
        }
    }

    /**
     * Get the handler for the given coin type.
     *
     * @param coinType protocol coin type
     * @return the handler, or {@code null} if none registered
     */
    public AbstractServiceHandler getHandler(int coinType) {
        return handlers.get(coinType);
    }

    /**
     * Register or replace a handler for the given coin type.
     *
     * @param coinType protocol coin type
     * @param handler  the handler to register
     */
    public void putHandler(int coinType, AbstractServiceHandler handler) {
        handlers.put(coinType, handler);
    }

    /**
     * Get the set of coin types that have registered handlers.
     *
     * @return unmodifiable copy of the coin type set
     */
    public Set<Integer> getHandlerCoinTypes() {
        return Collections.unmodifiableSet(Set.copyOf(handlers.keySet()));
    }

}
