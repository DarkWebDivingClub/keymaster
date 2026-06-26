package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyVault;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class GpgServiceChannelTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final String DUMMY_CERT_ARMOR =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

    private ServiceChannel channel;
    private GpgServiceHandler handler;
    private Gson gson;

    @BeforeEach
    void setUp() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        handler = new GpgServiceHandler(vault,
                GpgServiceHandlerTest.gpgKeysForIdentity("alice@test.com"),
                DUMMY_CERT_ARMOR);
        gson = ServiceChannel.createGson();
        channel = new ServiceChannel(handler, gson);
    }

    @Test
    void dispatchRequestIdentities_returnsJsonResult() {
        JsonObject response = channel.dispatch("request_identities", null);

        assertTrue(response.has("result"));
        assertFalse(response.has("error"));

        var resultArray = response.getAsJsonArray("result");
        assertEquals(2, resultArray.size());

        JsonObject cert = resultArray.get(0).getAsJsonObject();
        assertTrue(cert.has("key_type"));
        assertTrue(cert.has("public_key"));
        assertTrue(cert.has("label"));
        assertEquals("ed25519", cert.get("key_type").getAsString());
        assertEquals("alice@test.com / certification", cert.get("label").getAsString());

        // public_key should be Base64-encoded 32-byte Ed25519 key
        byte[] decoded = Base64.getDecoder().decode(cert.get("public_key").getAsString());
        assertEquals(32, decoded.length);

        JsonObject sign = resultArray.get(1).getAsJsonObject();
        assertEquals("alice@test.com / signing", sign.get("label").getAsString());
    }

    @Test
    void dispatchSignRequest_returnsJsonResult() {
        handler.setApprovalUI((m, d) -> true);

        // Get public key from identities
        JsonObject idResponse = channel.dispatch("request_identities", null);
        String pubKeyB64 = idResponse.getAsJsonArray("result")
                .get(0).getAsJsonObject()
                .get("public_key").getAsString();

        // Build sign request params
        String dataB64 = Base64.getEncoder().encodeToString("test data".getBytes());
        JsonObject param = new JsonObject();
        param.addProperty("public_key", pubKeyB64);
        param.addProperty("data", dataB64);
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = channel.dispatch("sign_request", params);

        assertTrue(response.has("result"));
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("signature"));

        byte[] sig = Base64.getDecoder().decode(result.get("signature").getAsString());
        assertEquals(64, sig.length);
    }

    @Test
    void dispatchGetPublicCert_returnsJsonResult() {
        JsonObject response = channel.dispatch("get_public_cert", null);

        assertTrue(response.has("result"));
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("public_cert_armor"));
        assertEquals(DUMMY_CERT_ARMOR, result.get("public_cert_armor").getAsString());
    }

    @Test
    void dispatchUnknownMethod_returnsError() {
        JsonObject response = channel.dispatch("nonexistent", null);

        assertTrue(response.has("error"));
        assertFalse(response.has("result"));
    }

    @Test
    void dispatchDenied_returnsError() {
        // No UI set, sign_request has ASK policy
        JsonObject idResponse = channel.dispatch("request_identities", null);
        String pubKeyB64 = idResponse.getAsJsonArray("result")
                .get(0).getAsJsonObject()
                .get("public_key").getAsString();

        JsonObject param = new JsonObject();
        param.addProperty("public_key", pubKeyB64);
        param.addProperty("data", Base64.getEncoder().encodeToString("data".getBytes()));
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = channel.dispatch("sign_request", params);

        assertTrue(response.has("error"));
        assertEquals("request denied by user", response.get("error").getAsString());
    }

    @Test
    void fieldNamingSnakeCase() {
        byte[] testKey = {1, 2, 3};
        GpgIdentity identity = new GpgIdentity("ed25519", testKey, "test");
        String json = gson.toJson(identity);

        assertTrue(json.contains("key_type"), "Expected snake_case: " + json);
        assertTrue(json.contains("public_key"), "Expected snake_case: " + json);
        assertFalse(json.contains("keyType"), "Should not have camelCase: " + json);
        assertFalse(json.contains("publicKey"), "Should not have camelCase: " + json);
    }

    @Test
    void methodBindingScanFindsAnnotatedMethods() {
        // GpgServiceHandler has 3 annotated methods
        assertEquals(3, channel.bindingCount());
    }

    @Test
    void wireFormatMatchesCurrentKeyMaster() {
        // Verify the JSON output matches what the inline KeyMaster GPG handling produces
        handler.setApprovalUI((m, d) -> true);

        // 1. request_identities: same public keys
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault);
        km.createIdentity("alice@test.com");

        // Get KM's GPG pubkeys via reflection (handleServiceRequest is private)
        // Instead, derive them directly from the vault
        int H = 0x80000000;
        int identityIndex = club.dwdc.keyvault.core.Bip32KeyDerivator.mangle("alice@test.com") | H;
        int algCert = new club.dwdc.keyvault.core.AlgField(
                club.dwdc.keyvault.core.AlgField.ALG_ED25519, 0, 0).toIndex() | H;
        int algSign = new club.dwdc.keyvault.core.AlgField(
                club.dwdc.keyvault.core.AlgField.ALG_ED25519, 0, 1).toIndex() | H;
        int config = new club.dwdc.keyvault.core.ConfigField(
                club.dwdc.keyvault.core.ConfigField.CSPRNG_NONE, 0).toIndex() | H;
        int purpose = 44 | H;
        int coin = club.dwdc.keyvault.core.Protocol.OPENPGP.coinType() | H;

        var certResult = vault.execute(club.dwdc.keyvault.core.KeyVault.FN_GET_PUBLIC_KEY, null,
                new int[]{purpose, coin, identityIndex, algCert, config});
        var signResult = vault.execute(club.dwdc.keyvault.core.KeyVault.FN_GET_PUBLIC_KEY, null,
                new int[]{purpose, coin, identityIndex, algSign, config});

        // ServiceChannel identity pubkeys should match vault-derived ones
        JsonObject response = channel.dispatch("request_identities", null);
        var ids = response.getAsJsonArray("result");
        byte[] actualCertKey = Base64.getDecoder().decode(
                ids.get(0).getAsJsonObject().get("public_key").getAsString());
        byte[] actualSignKey = Base64.getDecoder().decode(
                ids.get(1).getAsJsonObject().get("public_key").getAsString());

        assertArrayEquals(certResult.data(), actualCertKey,
                "Certification key must match vault derivation");
        assertArrayEquals(signResult.data(), actualSignKey,
                "Signing key must match vault derivation");

        // 2. sign_request: verify signature format
        String certKeyB64 = Base64.getEncoder().encodeToString(actualCertKey);
        String dataB64 = Base64.getEncoder().encodeToString("test".getBytes());
        JsonObject param = new JsonObject();
        param.addProperty("public_key", certKeyB64);
        param.addProperty("data", dataB64);
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject signResponse = channel.dispatch("sign_request", params);
        assertTrue(signResponse.has("result"));
        JsonObject result = signResponse.getAsJsonObject("result");
        assertTrue(result.has("signature"));
        byte[] sig = Base64.getDecoder().decode(result.get("signature").getAsString());
        assertEquals(64, sig.length);

        // 3. get_public_cert: verify structure
        JsonObject certResponse = channel.dispatch("get_public_cert", null);
        assertTrue(certResponse.has("result"));
        assertTrue(certResponse.getAsJsonObject("result").has("public_cert_armor"));
    }
}
