package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link NipxxConnector} service request routing (no relay needed).
 */
class NipxxConnectorTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private NipxxConnector connector;
    private Realm realm;

    @BeforeEach
    void setUp() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);

        int mangledIdentity = Bip32KeyDerivator.mangle("alice@test.com");

        // Build SSH handler
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        KeyEntry sshKey = new KeyEntry(sshHdPath, Map.of("comment", "alice@test.com"));
        SshServiceHandler sshHandler = new SshServiceHandler(vault, List.of(sshKey));
        sshHandler.setApprovalUI((m, d) -> true);

        // Build GPG handler
        String[] roleNames = {"certification", "signing"};
        java.util.List<KeyEntry> gpgKeys = new java.util.ArrayList<>();
        for (int role = 0; role < roleNames.length; role++) {
            HDPath gpgHdPath = HDPath.m(
                    new ChildNumber(44, true),
                    new ChildNumber(Protocol.OPENPGP.coinType(), true),
                    new ChildNumber(mangledIdentity, true),
                    new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
                    new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
            );
            gpgKeys.add(new KeyEntry(gpgHdPath, Map.of(
                    "label", "alice@test.com / " + roleNames[role],
                    "key_type", "ed25519",
                    "identity", "alice@test.com",
                    "creation_time", "1700000000",
                    "pgp_name", "alice@test.com",
                    "pgp_email", "alice@test.com")));
        }
        GpgServiceHandler gpgHandler = new GpgServiceHandler(vault, gpgKeys);
        gpgHandler.setApprovalUI((m, d) -> true);

        realm = new Realm(1, "test", new Identity("alice@test.com"), vault);
        realm.putHandler(Protocol.SSH.coinType(), sshHandler);
        realm.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);

        connector = new NipxxConnector(realm);
    }

    @Test
    void handleServiceRequest_routesSsh() {
        JsonObject response = connector.handleServiceRequest("ssh", "request_identities", null);

        assertTrue(response.has("result"), "response must have 'result'");
        // Wire format wrapping: result should contain identities object
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("identities"), "result must have 'identities'");
        JsonArray identities = result.getAsJsonArray("identities");
        assertEquals(1, identities.size());

        JsonObject identity = identities.get(0).getAsJsonObject();
        assertTrue(identity.has("key_blob"));
        assertEquals("alice@test.com", identity.get("comment").getAsString());
    }

    @Test
    void handleServiceRequest_routesGpg() {
        JsonObject response = connector.handleServiceRequest("gpg", "request_identities", null);

        assertTrue(response.has("result"), "response must have 'result'");
        // GPG request_identities also gets wire-format wrapping
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("identities"), "result must have 'identities'");
    }

    @Test
    void handleServiceRequest_gpgGetPublicCert() {
        JsonObject response = connector.handleServiceRequest("gpg", "get_public_cert", null);

        assertTrue(response.has("result"), "response must have 'result'");
        assertFalse(response.has("error"));
    }

    @Test
    void handleServiceRequest_unknownService() {
        JsonObject response = connector.handleServiceRequest("ftp", "request_identities", null);

        assertTrue(response.has("error"));
        assertTrue(response.get("error").getAsString().contains("unknown service"));
    }

    @Test
    void handleServiceRequest_noHandler() {
        // Create connector with realm that only has SSH
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        Realm sshOnlyRealm = new Realm(2, "ssh-only", new Identity("alice@test.com"), vault);
        int mangledIdentity = Bip32KeyDerivator.mangle("alice@test.com");
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        sshOnlyRealm.putHandler(Protocol.SSH.coinType(),
                new SshServiceHandler(vault, List.of(new KeyEntry(sshHdPath, Map.of("comment", "test")))));

        NipxxConnector sshOnlyConnector = new NipxxConnector(sshOnlyRealm);

        // GPG is a known service type but has no handler registered
        JsonObject response = sshOnlyConnector.handleServiceRequest("gpg", "request_identities", null);

        assertTrue(response.has("error"));
        assertTrue(response.get("error").getAsString().contains("no handler"));
    }

    @Test
    void serviceTypeToCoinType_maps() {
        assertEquals(Protocol.SSH.coinType(), NipxxConnector.serviceTypeToCoinType("ssh"));
        assertEquals(Protocol.OPENPGP.coinType(), NipxxConnector.serviceTypeToCoinType("gpg"));
        assertNull(NipxxConnector.serviceTypeToCoinType("unknown"));
    }

    @Test
    void realmXpub_isDeterministicFromVault() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        int H = 0x80000000;
        int mangledRealm = Bip32KeyDerivator.mangle("keymaster:0");
        int[] realmBasePath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                mangledRealm | H,
                0 | H,
                0 | H
        };

        // Xpub path includes realmSeq (non-hardened) so avatar derives
        // service channels at 2 levels: protocol_index / seq
        int realmSeq = 0;
        int[] realmXpubPath = java.util.Arrays.copyOf(realmBasePath, realmBasePath.length + 1);
        realmXpubPath[realmBasePath.length] = realmSeq;

        // First derivation: FN_GET_PUBLIC_KEY → compressed key + chainCode → xpub
        VaultResult r1 = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, realmXpubPath);
        assertTrue(r1.isOk());
        assertNotNull(r1.chainCode());
        String xpub1 = HDKeyDerivation.createMasterPubKeyFromBytes(
                r1.data(), r1.chainCode())
                .serializePubB58(BitcoinNetwork.MAINNET);

        // Second derivation from a fresh vault with same mnemonic
        var vault2 = new Bip32KeyVault(TEST_MNEMONIC);
        VaultResult r2 = vault2.execute(KeyVault.FN_GET_PUBLIC_KEY, null, realmXpubPath);
        String xpub2 = HDKeyDerivation.createMasterPubKeyFromBytes(
                r2.data(), r2.chainCode())
                .serializePubB58(BitcoinNetwork.MAINNET);

        assertEquals(xpub1, xpub2, "realm xpub must be deterministic across vault instances");
    }

    @Test
    void mangle_keymaster0_goldenValue() {
        assertEquals(0x404a4890, Bip32KeyDerivator.mangle("keymaster:0"));
    }
}
