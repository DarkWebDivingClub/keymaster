package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.util.NostrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final int ALG_SCHNORR =
            new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H;
    private static final int DEFAULT_CONFIG =
            new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H;

    private final KeyVault vault;
    private final int[] path;
    private final byte[] privKey;
    private final byte[] pubKey;
    private final String pubKeyHex;

    private NostrTransport transport;
    private String avatarPubKeyHex;

    /**
     * Create a KeyMaster from a BIP-39 mnemonic and a login identity.
     *
     * @param mnemonic BIP-39 mnemonic phrase
     * @param identity login identity (e.g. "alice@atlanta.com")
     */
    public KeyMaster(String mnemonic, String identity) {
        this.vault = new Bip32KeyVault(mnemonic);

        int identityIndex = Bip32KeyDerivator.mangle(identity) | H;
        this.path = new int[]{PURPOSE, NOSTR_COIN, identityIndex, ALG_SCHNORR, DEFAULT_CONFIG};

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

        log.info("KeyMaster identity: {}", pubKeyHex);
    }

    /**
     * The Nostr transport public key (hex-encoded, 64 characters).
     */
    public String getPubKeyHex() {
        return pubKeyHex;
    }

    /**
     * Connect to a Nostr relay.
     */
    public void connectToRelay(String relayUrl) throws InterruptedException {
        this.transport = new NostrTransport(privKey, pubKey);
        transport.connect(relayUrl);
    }

    /**
     * Attach to an Avatar identified by its Schnorr public key.
     *
     * @param avatarPubKeyHex Avatar's transport public key (hex)
     * @return session event ID
     */
    public String attach(String avatarPubKeyHex) throws Exception {
        if (transport == null) {
            throw new IllegalStateException("Not connected to relay");
        }
        this.avatarPubKeyHex = avatarPubKeyHex;
        return transport.sendAttach(avatarPubKeyHex);
    }

    /**
     * Detach from the currently attached Avatar.
     */
    public void detach() throws Exception {
        if (transport == null || avatarPubKeyHex == null) {
            log.warn("No active session to detach");
            return;
        }
        transport.sendDetach(avatarPubKeyHex);
        avatarPubKeyHex = null;
    }

    /**
     * Close the relay connection and release resources.
     */
    public void close() {
        if (transport != null) {
            transport.close();
        }
    }
}
