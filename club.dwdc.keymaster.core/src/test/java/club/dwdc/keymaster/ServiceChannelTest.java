package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ServiceChannelTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private ServiceChannel channel;
    private SshServiceHandler handler;
    private Gson gson;

    @BeforeEach
    void setUp() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        handler = new SshServiceHandler(vault, List.of(SshServiceHandlerTest.sshKeyEntry("alice@test.com")));
        gson = ServiceChannel.createGson();
        channel = new ServiceChannel(handler, gson);
    }

    @Test
    void dispatchRequestIdentities_returnsJsonResult() {
        JsonObject response = channel.dispatch("request_identities", null);

        assertTrue(response.has("result"));
        assertFalse(response.has("error"));

        // Result should be a JSON array of identity objects
        var resultArray = response.getAsJsonArray("result");
        assertEquals(1, resultArray.size());

        JsonObject identity = resultArray.get(0).getAsJsonObject();
        assertTrue(identity.has("key_blob"));
        assertTrue(identity.has("comment"));
        assertEquals("alice@test.com", identity.get("comment").getAsString());

        // key_blob should be a valid Base64 string
        String keyBlobB64 = identity.get("key_blob").getAsString();
        byte[] decoded = Base64.getDecoder().decode(keyBlobB64);
        assertEquals(51, decoded.length);
    }

    @Test
    void dispatchSignRequest_returnsJsonResult() {
        handler.setApprovalUI((m, d) -> true);

        // First get the key blob via identities
        JsonObject idResponse = channel.dispatch("request_identities", null);
        String keyBlobB64 = idResponse.getAsJsonArray("result")
                .get(0).getAsJsonObject()
                .get("key_blob").getAsString();

        // Build sign request params
        String dataB64 = Base64.getEncoder().encodeToString("test data".getBytes());
        JsonObject param = new JsonObject();
        param.addProperty("key_blob", keyBlobB64);
        param.addProperty("data", dataB64);
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = channel.dispatch("sign_request", params);

        assertTrue(response.has("result"));
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("signature"));
        assertTrue(result.has("key_type"));
        assertEquals("ssh-ed25519", result.get("key_type").getAsString());

        // Signature should be Base64-encoded 64-byte Ed25519 signature
        byte[] sig = Base64.getDecoder().decode(result.get("signature").getAsString());
        assertEquals(64, sig.length);
    }

    @Test
    void dispatchUnknownMethod_returnsError() {
        JsonObject response = channel.dispatch("nonexistent", null);

        assertTrue(response.has("error"));
        assertFalse(response.has("result"));
        assertTrue(response.get("error").getAsString().contains("unknown method"));
    }

    @Test
    void dispatchDenied_returnsError() {
        // No UI set, sign_request has ASK policy
        // First get the key blob
        JsonObject idResponse = channel.dispatch("request_identities", null);
        String keyBlobB64 = idResponse.getAsJsonArray("result")
                .get(0).getAsJsonObject()
                .get("key_blob").getAsString();

        JsonObject param = new JsonObject();
        param.addProperty("key_blob", keyBlobB64);
        param.addProperty("data", Base64.getEncoder().encodeToString("data".getBytes()));
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = channel.dispatch("sign_request", params);

        assertTrue(response.has("error"));
        assertEquals("request denied by user", response.get("error").getAsString());
    }

    @Test
    void base64RoundTrip() {
        byte[] original = {0, 1, 2, (byte) 0xFF, (byte) 0xFE, 127, -128};

        // Serialize
        String json = gson.toJson(original);
        // Should be a Base64 string, not a JSON array
        assertTrue(json.startsWith("\""));

        // Deserialize
        byte[] roundTripped = gson.fromJson(json, byte[].class);
        assertArrayEquals(original, roundTripped);
    }

    @Test
    void fieldNamingSnakeCase() {
        // SshIdentity has keyBlob → should become key_blob in JSON
        byte[] testBlob = {1, 2, 3};
        SshIdentity identity = new SshIdentity(testBlob, "test");
        String json = gson.toJson(identity);

        assertTrue(json.contains("key_blob"), "Expected snake_case field: " + json);
        assertFalse(json.contains("keyBlob"), "Should not have camelCase: " + json);
    }

    @Test
    void methodBindingScanFindsAnnotatedMethods() {
        // SshServiceHandler has 2 annotated methods: request_identities, sign_request
        assertEquals(2, channel.bindingCount());
    }

    @Test
    void wireFormatMatchesCurrentKeyMaster() {
        // Verify the JSON output structure matches what KeyMaster produces

        // 1. Test request_identities format
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault);
        km.createIdentity("alice@test.com");

        // Get KeyMaster's SSH identity blob for comparison
        int H = 0x80000000;
        int identityIndex = Bip32KeyDerivator.mangle("alice@test.com") | H;
        int[] sshPath = {44 | H, Protocol.SSH.coinType() | H, identityIndex,
                new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H, 0 | H};
        var pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        byte[] expectedBlob = SshServiceHandler.buildSshEd25519KeyBlob(pubResult.data());

        // ServiceChannel identity blob should match
        JsonObject response = channel.dispatch("request_identities", null);
        String actualBlobB64 = response.getAsJsonArray("result")
                .get(0).getAsJsonObject()
                .get("key_blob").getAsString();
        byte[] actualBlob = Base64.getDecoder().decode(actualBlobB64);

        assertArrayEquals(expectedBlob, actualBlob,
                "ServiceChannel blob must match KeyMaster blob");

        // 2. Test sign_request format: response should have "signature" and "key_type"
        handler.setApprovalUI((m, d) -> true);
        String blobB64 = Base64.getEncoder().encodeToString(actualBlob);
        String dataB64 = Base64.getEncoder().encodeToString("test".getBytes());
        JsonObject param = new JsonObject();
        param.addProperty("key_blob", blobB64);
        param.addProperty("data", dataB64);
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject signResponse = channel.dispatch("sign_request", params);
        assertTrue(signResponse.has("result"));
        JsonObject signResult = signResponse.getAsJsonObject("result");
        assertTrue(signResult.has("signature"));
        assertTrue(signResult.has("key_type"));
        assertEquals("ssh-ed25519", signResult.get("key_type").getAsString());
    }

    // ── Session-based constructor tests ──────────────────────────────────

    @Test
    void dispatchViaSession_resolvesHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        SshServiceHandler sshHandler = new SshServiceHandler(
                vault, List.of(SshServiceHandlerTest.sshKeyEntry("alice@test.com")));

        Session session = new Session();
        session.putHandler(Protocol.SSH.coinType(), sshHandler);

        ServiceChannel sessionChannel = new ServiceChannel(
                session, Protocol.SSH.coinType(), ServiceChannel.createGson());

        JsonObject response = sessionChannel.dispatch("request_identities", null);

        assertTrue(response.has("result"));
        assertFalse(response.has("error"));
        var resultArray = response.getAsJsonArray("result");
        assertEquals(1, resultArray.size());
        assertEquals("alice@test.com",
                resultArray.get(0).getAsJsonObject().get("comment").getAsString());
    }

    @Test
    void sessionHandlerReplacement_usesNewHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        SshServiceHandler handler1 = new SshServiceHandler(
                vault, List.of(SshServiceHandlerTest.sshKeyEntry("alice@test.com")));

        Session session = new Session();
        session.putHandler(Protocol.SSH.coinType(), handler1);

        ServiceChannel sessionChannel = new ServiceChannel(
                session, Protocol.SSH.coinType(), ServiceChannel.createGson());

        // First dispatch uses handler1
        JsonObject response1 = sessionChannel.dispatch("request_identities", null);
        assertEquals("alice@test.com",
                response1.getAsJsonArray("result").get(0).getAsJsonObject()
                        .get("comment").getAsString());

        // Replace handler in session
        SshServiceHandler handler2 = new SshServiceHandler(
                vault, List.of(SshServiceHandlerTest.sshKeyEntry("bob@test.com")));
        session.putHandler(Protocol.SSH.coinType(), handler2);

        // Next dispatch picks up the new handler
        JsonObject response2 = sessionChannel.dispatch("request_identities", null);
        assertEquals("bob@test.com",
                response2.getAsJsonArray("result").get(0).getAsJsonObject()
                        .get("comment").getAsString());
    }
}
