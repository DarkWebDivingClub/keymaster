package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import club.dwdc.keyexporter.core.OpenPgpSeedDeriver;
import club.dwdc.keyexporter.openpgp.OpenPgpExport;
import club.dwdc.keyexporter.openpgp.OpenPgpExporter;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.bouncycastle.openpgp.PGPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Orchestrates identity creation, session building, and attach/detach lifecycle.
 *
 * <p>Wraps a passive {@link KeyMaster} (state holder) and drives the workflow:
 * derive identity keys, build service handlers, create sessions, and manage
 * connector lifecycle.
 */
public class KeyMasterController {

    private static final Logger log = LoggerFactory.getLogger(KeyMasterController.class);

    private final KeyMaster km;
    private final KeyMetaDataStore keyStore;
    private ApprovalHandler approvalHandler;

    /**
     * Create a controller without a key metadata store (direct mode).
     *
     * @param km the KeyMaster state holder
     */
    public KeyMasterController(KeyMaster km) {
        this(km, null);
    }

    /**
     * Create a controller with a key metadata store for persistent key tracking.
     *
     * @param km       the KeyMaster state holder
     * @param keyStore metadata store for key entries and identity mappings, or {@code null}
     */
    public KeyMasterController(KeyMaster km, KeyMetaDataStore keyStore) {
        this.km = km;
        this.keyStore = keyStore;
    }

    /**
     * Create (or re-derive) an identity: derive keys, build handlers, and populate session.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     */
    public void createIdentity(String identity) {
        // 1. Derive Nostr key pair from vault
        km.deriveIdentity(identity);

        KeyVault vault = km.getVault();
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        // 2. Generate GPG public cert for this identity
        String gpgPublicCertArmor;
        try {
            OpenPgpKeySeeds gpgSeeds = OpenPgpSeedDeriver.derive(vault, identity);
            OpenPgpMetadata gpgMetadata = OpenPgpMetadata.create(
                    identity, identity, identity, Instant.ofEpochSecond(1));
            OpenPgpExport gpgExport = OpenPgpExporter.export(
                    gpgSeeds, gpgMetadata, "keymaster".toCharArray());
            gpgPublicCertArmor = gpgExport.publicKeyArmor();
        } catch (PGPException | IOException e) {
            throw new IllegalStateException("Failed to generate GPG cert", e);
        }

        // 3. Build SSH service handler
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        KeyEntry sshKey = new KeyEntry(sshHdPath, Map.of("comment", identity));
        SshServiceHandler sshHandler = new SshServiceHandler(vault, List.of(sshKey));
        if (approvalHandler != null) {
            sshHandler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "ssh"));
        }

        // 4. Build GPG service handler
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
                    "key_type", "ed25519")));
        }
        GpgServiceHandler gpgHandler = new GpgServiceHandler(vault, gpgKeys, gpgPublicCertArmor);
        if (approvalHandler != null) {
            gpgHandler.setApprovalUI(new ApprovalHandlerAdapter(approvalHandler, "gpg"));
        }

        // 5. Create session and register handlers
        Session session = new Session();
        session.putHandler(Protocol.SSH.coinType(), sshHandler);
        session.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);
        km.setSession(session);

        // 6. Store key entries in metadata store if present
        if (keyStore != null) {
            keyStore.addIdentity(identity);
            keyStore.addKey(sshKey);
            for (KeyEntry gpgKey : gpgKeys) {
                keyStore.addKey(gpgKey);
            }
        }

        log.info("Identity created: {}", km.getPubKeyHex());
    }

    /**
     * Set an approval handler for incoming service requests.
     *
     * <p>When set, every service request is passed through the handler before
     * processing. If a session is already active, propagates to all handlers
     * with per-service-type adapters.
     *
     * @param handler approval handler, or {@code null} to auto-approve
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
        Session session = km.getSession();
        if (session != null) {
            for (int coinType : session.getHandlerCoinTypes()) {
                AbstractServiceHandler h = session.getHandler(coinType);
                if (h != null) {
                    String serviceType = coinType == Protocol.SSH.coinType() ? "ssh" : "gpg";
                    h.setApprovalUI(handler != null
                            ? new ApprovalHandlerAdapter(handler, serviceType)
                            : null);
                }
            }
        }
    }

    /**
     * Attach to an Avatar described by the given descriptor.
     *
     * @param avatar descriptor with relay URL, login xpub, and services
     * @return session event ID
     * @throws IllegalStateException if no identity has been created
     */
    public String attach(AvatarDescriptor avatar) throws Exception {
        if (km.getPubKeyHex() == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }
        NipxxConnector conn = new NipxxConnector(
                km.getSession(), km.getRealmDerivator(), km.getPubKeyHex(), km.getPrivKey());
        String sessionId = conn.connect(avatar);
        km.setConnector(conn);
        return sessionId;
    }

    /**
     * Detach from the currently attached Avatar and close the relay connection.
     */
    public void detach() throws Exception {
        Connector connector = km.getConnector();
        if (connector == null) {
            log.warn("No active session to detach");
            return;
        }
        connector.disconnect();
        km.setConnector(null);
    }

    /**
     * Returns the wrapped KeyMaster for read-only state access.
     */
    public KeyMaster getKeyMaster() {
        return km;
    }
}
