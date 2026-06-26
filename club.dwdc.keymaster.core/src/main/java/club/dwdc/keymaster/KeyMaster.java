package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import club.dwdc.keyexporter.core.OpenPgpKeySeeds;
import club.dwdc.keyexporter.core.OpenPgpMetadata;
import club.dwdc.keyexporter.core.OpenPgpSeedDeriver;
import club.dwdc.keyexporter.openpgp.OpenPgpExport;
import club.dwdc.keyexporter.openpgp.OpenPgpExporter;
import nostr.util.NostrUtil;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.bouncycastle.openpgp.PGPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * KeyMaster — controller and security authority for the DWDC Key System.
 *
 * <p>Loads a BIP-39 mnemonic, derives a Nostr identity key from the vault,
 * and communicates with an Avatar over a Nostr relay using NIP-44 encrypted
 * kind-27235 events.</p>
 */
public class KeyMaster {
    private static final Logger log = LoggerFactory.getLogger(KeyMaster.class);

    private static final int H = 0x80000000;
    private static final int PURPOSE = 44 | H;
    private static final int NOSTR_COIN = Protocol.NOSTR.coinType() | H;
    private static final int SSH_COIN = Protocol.SSH.coinType() | H;
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int ALG_ED25519_USER_AUTH =
            new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault;
    private ApprovalHandler approvalHandler;

    private int[] path;
    private byte[] privKey;
    private byte[] pubKey;
    private String pubKeyHex;
    private String currentIdentity;

    /** BIP-32 derivator for realm (transport) keys — separate from vault identity keys. */
    private final Bip32KeyDerivator realmDerivator;

    private Session session;
    private Connector connector;

    /**
     * Create a KeyMaster from a ready-to-use KeyVault.
     *
     * <p>Initializes a random realm transport seed.
     * Call {@link #createIdentity(String)} to derive the transport key for an identity.
     *
     * @param vault KeyVault instance for cryptographic operations
     */
    public KeyMaster(KeyVault vault) {
        this.vault = vault;
        byte[] realmSeed = new byte[64];
        new SecureRandom().nextBytes(realmSeed);
        this.realmDerivator = new Bip32KeyDerivator(realmSeed);
    }

    /**
     * Create a KeyMaster from a KeyVault with a specified realm transport seed.
     * This constructor is useful for testing determinism.
     *
     * @param vault     KeyVault instance for cryptographic operations
     * @param realmSeed 64-byte seed for the realm BIP-32 derivator
     */
    public KeyMaster(KeyVault vault, byte[] realmSeed) {
        this.vault = vault;
        this.realmDerivator = new Bip32KeyDerivator(realmSeed);
    }

    /**
     * Set an approval handler for incoming service requests.
     *
     * <p>When set, every service request is passed through the handler before
     * processing. When {@code null} (the default), all requests are auto-approved
     * for backward compatibility.
     *
     * @param handler approval handler, or {@code null} to auto-approve
     */
    public void setApprovalHandler(ApprovalHandler handler) {
        this.approvalHandler = handler;
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
     * Create (or re-derive) an identity, deriving the Nostr transport key.
     *
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     */
    public void createIdentity(String identity) {
        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        this.path = new int[]{PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};
        this.currentIdentity = identity;

        VaultResult seedResult = vault.execute(KeyVault.FN_EXPORT_SEED, null, path);
        if (!seedResult.isOk()) {
            throw new IllegalStateException("Vault FN_EXPORT_SEED failed: status=" + seedResult.status());
        }
        this.privKey = seedResult.data();

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Vault FN_GET_PUBLIC_KEY failed: status=" + pubResult.status());
        }
        this.pubKey = pubResult.data();
        this.pubKeyHex = NostrUtil.bytesToHex(pubKey);

        // Generate GPG public cert for this identity.
        // Fixed timestamp for deterministic fingerprints (same identity → same cert).
        // Uses epoch+1 because GnuPG 2.2.x rejects back-signatures with timestamp 0.
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

        int mangledIdentity = Bip32KeyDerivator.mangle(identity);

        // Build SSH service handler
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

        // Build GPG service handler
        String[] roleNames = {"certification", "signing"};
        List<KeyEntry> gpgKeys = new java.util.ArrayList<>();
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

        // Populate session with handlers
        this.session = new Session();
        session.putHandler(Protocol.SSH.coinType(), sshHandler);
        session.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);

        log.info("KeyMaster identity: {}", pubKeyHex);
    }

    /**
     * The Nostr transport public key (hex-encoded, 64 characters).
     */
    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /**
     * Derive the realm xpub at the given realm index.
     * The realm xpub is shared with the Avatar so it can derive service pubkeys.
     *
     * @param realmIndex non-hardened child index (typically 0)
     * @return Base58Check-encoded xpub string
     */
    public String deriveRealmXpub(int realmIndex) {
        return realmDerivator.deriveXpub(realmIndex);
    }

    /**
     * Derive the realm private key bytes at the given realm index.
     * Used as the Nostr transport signing key for the realm.
     *
     * @param realmIndex non-hardened child index (typically 0)
     * @return 32-byte private key
     */
    public byte[] deriveRealmPrivKey(int realmIndex) {
        return realmDerivator.derive(realmIndex);
    }

    /**
     * Derive a service channel private key from the realm.
     * Path: realmIndex / mangle(serviceType) / seq
     *
     * @param realmIndex  realm child index
     * @param serviceType service identifier (e.g. "ssh")
     * @param seq         sequence number
     * @return 32-byte private key
     */
    public byte[] deriveRealmServiceKey(int realmIndex, String serviceType, int seq) {
        int protocolIdx = Bip32KeyDerivator.mangle(serviceType);
        return realmDerivator.derive(realmIndex, protocolIdx, seq);
    }

    /**
     * Get the realm derivator (for use by NostrTransport).
     */
    Bip32KeyDerivator getRealmDerivator() {
        return realmDerivator;
    }

    /**
     * Attach to an Avatar described by the given descriptor.
     *
     * <p>Creates a {@link NipxxConnector}, connects to the relay, sends the
     * attach request, and returns the session event ID.
     *
     * @param avatar descriptor with relay URL, login xpub, and services
     * @return session event ID
     */
    public String attach(AvatarDescriptor avatar) throws Exception {
        if (privKey == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }
        NipxxConnector conn = new NipxxConnector(session, realmDerivator, pubKeyHex, privKey);
        String sessionId = conn.connect(avatar);
        this.connector = conn;
        return sessionId;
    }

    /**
     * Detach from the currently attached Avatar and close the relay connection.
     */
    public void detach() throws Exception {
        if (connector == null) {
            log.warn("No active session to detach");
            return;
        }
        connector.disconnect();
        connector = null;
    }

    /**
     * Returns the SSH authorized_keys line for the current identity's Ed25519 key.
     * Format: {@code ssh-ed25519 <base64-key-blob> <identity>}
     */
    public String getSshAuthorizedKeysLine() {
        if (currentIdentity == null) {
            throw new IllegalStateException("No identity — call createIdentity() first");
        }
        int identityIndex = Bip32KeyDerivator.mangle(currentIdentity) | H;
        int[] sshPath = new int[]{PURPOSE, SSH_COIN, identityIndex, ALG_ED25519_USER_AUTH, DEFAULT_CONFIG};

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Failed to derive SSH key: status=" + pubResult.status());
        }

        byte[] keyBlob = SshServiceHandler.buildSshEd25519KeyBlob(pubResult.data());
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(keyBlob) + " " + currentIdentity;
    }
}
