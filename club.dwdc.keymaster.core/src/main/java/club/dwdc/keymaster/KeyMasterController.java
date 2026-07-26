package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import nostr.util.NostrUtil;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
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
    private ApprovalHandler approvalHandler;
    private String currentIdentity;
    private Consumer<NostrTransport.ConnectionState> connectionStateListener;

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
        KeyVault vault = km.vault;
        KeyMetaDataStore keyStore = km.keyMetaDataStore;
        if (keyStore == null) {
            throw new IllegalStateException("Metadata store is required for createIdentity");
        }
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);
        long creationTime = Instant.now().getEpochSecond();

        // 1. SSH key entry — metadata-only
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        KeyEntry sshKey = new KeyEntry(sshHdPath, Map.of("comment", identity));

        // 2. GPG key entries (certification + signing) — metadata-only
        String[] roleNames = {"certification", "signing"};
        List<KeyEntry> gpgKeys = new ArrayList<>();
        for (int role = 0; role < roleNames.length; role++) {
            HDPath gpgHdPath = HDPath.m(
                    new ChildNumber(44, true),
                    new ChildNumber(Protocol.OPENPGP.coinType(), true),
                    new ChildNumber(mangledIdentity, true),
                    new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
                    new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
            );
            gpgKeys.add(new KeyEntry(gpgHdPath, Map.of(
                    "label", identity + " / " + roleNames[role],
                    "key_type", "ed25519",
                    "identity", identity,
                    "creation_time", String.valueOf(creationTime),
                    "pgp_name", pgpName,
                    "pgp_email", pgpEmail)));
        }

        // 3. Nostr key entry — metadata-only
        HDPath nostrHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.NOSTR.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        KeyEntry nostrKey = new KeyEntry(nostrHdPath, Map.of("identity", identity));

        // 4. MLS signing key entry — metadata-only
        HDPath mlsHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.MLS.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        KeyEntry mlsKey = new KeyEntry(mlsHdPath, Map.of("identity", identity));

        // Store in metadata store
        keyStore.addIdentity(identity);
        keyStore.addKey(sshKey);
        for (KeyEntry gpgKey : gpgKeys) {
            keyStore.addKey(gpgKey);
        }
        keyStore.addKey(nostrKey);
        keyStore.addKey(mlsKey);

        // 6. Derive pubkey from vault (no private key export)
        int identityIndex = mangledIdentity | H;
        int[] nostrPath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                identityIndex,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
        String pubkey = NostrUtil.bytesToHex(
                vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data());

        log.info("Identity created: {}", pubkey);
        return pubkey;
    }

    /**
     * Set an approval handler for incoming service requests.
     *
     * <p>When set, every service request is passed through the handler before
     * processing. If a realm is already active, propagates to all handlers
     * with per-service-type adapters.
     *
     * @param handler approval handler, or {@code null} to auto-approve
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
        if (currentIdentity != null) {
            Realm realm = km.realms.get(currentIdentity);
            if (realm != null) {
                for (int coinType : realm.getHandlerCoinTypes()) {
                    AbstractServiceHandler h = realm.getHandler(coinType);
                    if (h != null) {
                        String serviceType = coinType == Protocol.SSH.coinType() ? "ssh" : "gpg";
                        h.setApprovalUI(handler != null
                                ? new ApprovalHandlerAdapter(handler, serviceType)
                                : null);
                    }
                }
            }
        }
    }

    /**
     * Attach to an Avatar: resolve keys from store, build realm and handlers,
     * create signer, build connector, connect.
     *
     * @param avatar   descriptor with relay URL, login xpub, and services
     * @param identity the identity to attach
     * @return attach event ID
     * @throws IllegalStateException if no metadata store is available
     */
    public String attach(AvatarDescriptor avatar, String identity) throws Exception {
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        // Resolve key entries from metadata store
        List<KeyEntry> allKeys;
        if (km.keyMetaDataStore != null) {
            allKeys = km.keyMetaDataStore.keysByIdentity(mangledIdentity);
        } else if (km.kvMetaStore != null) {
            allKeys = km.kvMetaStore.byIdentity(identity).stream()
                    .map(AbstractKeyEntry::toKeyEntry)
                    .collect(Collectors.toList());
        } else {
            throw new IllegalStateException("Metadata store is required for attach");
        }
        return doAttach(avatar, identity, allKeys);
    }

    /**
     * Attach with additional key predicates for multi-identity scenarios.
     * Keys matching any predicate are included in the attach.
     *
     * @param avatar     descriptor with relay URL, login xpub, and services
     * @param identity   the primary identity to attach
     * @param predicates key selection predicates (match by identity, etc.)
     * @return attach event ID
     */
    public String attach(AvatarDescriptor avatar, String identity,
                         List<Predicate<AbstractKeyEntry>> predicates) throws Exception {
        if (km.kvMetaStore == null) {
            return attach(avatar, identity);
        }
        // Collect keys from all entries matching any predicate
        List<KeyEntry> allKeys = km.kvMetaStore.all().stream()
                .filter(entry -> predicates.stream().anyMatch(p -> p.test(entry)))
                .map(AbstractKeyEntry::toKeyEntry)
                .collect(Collectors.toList());
        return doAttach(avatar, identity, allKeys);
    }

    private String doAttach(AvatarDescriptor avatar, String identity,
                            List<KeyEntry> allKeys) throws Exception {
        this.currentIdentity = identity;
        KeyVault vault = km.vault;
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        List<KeyEntry> sshKeys = allKeys.stream()
                .filter(k -> k.coinType() == Protocol.SSH.coinType())
                .collect(Collectors.toList());
        List<KeyEntry> gpgKeys = allKeys.stream()
                .filter(k -> k.coinType() == Protocol.OPENPGP.coinType())
                .collect(Collectors.toList());
        List<KeyEntry> nostrKeys = allKeys.stream()
                .filter(k -> k.coinType() == Protocol.NOSTR.coinType())
                .collect(Collectors.toList());

        // Build service handlers
        SshServiceHandler sshHandler = new SshServiceHandler(vault, sshKeys);
        GpgServiceHandler gpgHandler = new GpgServiceHandler(vault, gpgKeys);
        NostrServiceHandler nostrHandler = new NostrServiceHandler(vault, nostrKeys);

        if (approvalHandler != null) {
            sshHandler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "ssh"));
            gpgHandler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "gpg"));
            nostrHandler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "nostr"));
        }

        // Create realm and register handlers
        Realm realm = new Realm();
        realm.putHandler(Protocol.SSH.coinType(), sshHandler);
        realm.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);
        realm.putHandler(Protocol.NOSTR.coinType(), nostrHandler);
        km.realms.put(identity, realm);

        // Create vault-backed Nostr signer
        int identityIndex = mangledIdentity | H;
        int[] nostrPath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                identityIndex,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };

        NostrIdentitySigner signer = new NostrIdentitySigner() {
            @Override
            public String getPubkey() {
                return NostrUtil.bytesToHex(
                        vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data());
            }

            @Override
            public byte[] sign(byte[] hash) {
                return vault.execute(KeyVault.FN_SIGN, hash, nostrPath).data();
            }
        };

        // Create connector and connect
        NipxxConnector conn = new NipxxConnector(realm);
        if (connectionStateListener != null) {
            conn.setConnectionStateListener(connectionStateListener);
        }
        String attachId = conn.connect(avatar, signer);
        km.connectors.put(identity, conn);
        return attachId;
    }

    /**
     * Detach from the currently attached Avatar and close the relay connection.
     */
    public void detach() throws Exception {
        if (currentIdentity == null) {
            log.warn("No active session to detach");
            return;
        }
        Connector connector = km.connectors.get(currentIdentity);
        if (connector == null) {
            log.warn("No active session to detach");
            return;
        }
        connector.disconnect();
        km.connectors.remove(currentIdentity);
    }

    /**
     * Set a listener for relay connection state changes (CONNECTED, RETRYING,
     * DISCONNECTED).  Propagated to the connector/transport on attach.
     *
     * @param listener state consumer, or {@code null} to clear
     */
    public void setConnectionStateListener(Consumer<NostrTransport.ConnectionState> listener) {
        this.connectionStateListener = listener;
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
     * Returns the current identity name, or {@code null}.
     */
    public String getCurrentIdentity() {
        return currentIdentity;
    }

    /**
     * Returns the wrapped KeyMaster for read-only state access.
     */
    public KeyMaster getKeyMaster() {
        return km;
    }
}
