package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bitcoinj.crypto.ChildNumber;
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
    private Session session;

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
                    "key_type", "ed25519")));
        }

        // Generate GPG cert for handler
        String gpgCertArmor;
        try {
            var gpgSeeds = club.dwdc.keyexporter.core.OpenPgpSeedDeriver.derive(vault, "alice@test.com");
            var gpgMetadata = club.dwdc.keyexporter.core.OpenPgpMetadata.create(
                    "alice@test.com", "alice@test.com", "alice@test.com",
                    java.time.Instant.ofEpochSecond(1));
            var gpgExport = club.dwdc.keyexporter.openpgp.OpenPgpExporter.export(
                    gpgSeeds, gpgMetadata, "keymaster".toCharArray());
            gpgCertArmor = gpgExport.publicKeyArmor();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        GpgServiceHandler gpgHandler = new GpgServiceHandler(vault, gpgKeys, gpgCertArmor);
        gpgHandler.setApprovalUI((m, d) -> true);

        session = new Session();
        session.putHandler(Protocol.SSH.coinType(), sshHandler);
        session.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);

        connector = new NipxxConnector(
                session, new Bip32KeyDerivator(new byte[64]), "", new byte[32]);
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
        // Create connector with session that only has SSH
        Session sshOnlySession = new Session();
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        int mangledIdentity = Bip32KeyDerivator.mangle("alice@test.com");
        HDPath sshHdPath = HDPath.m(
                new ChildNumber(44, true),
                new ChildNumber(Protocol.SSH.coinType(), true),
                new ChildNumber(mangledIdentity, true),
                new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
                new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        sshOnlySession.putHandler(Protocol.SSH.coinType(),
                new SshServiceHandler(vault, List.of(new KeyEntry(sshHdPath, Map.of("comment", "test")))));

        NipxxConnector sshOnlyConnector = new NipxxConnector(
                sshOnlySession, new Bip32KeyDerivator(new byte[64]), "", new byte[32]);

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
}
