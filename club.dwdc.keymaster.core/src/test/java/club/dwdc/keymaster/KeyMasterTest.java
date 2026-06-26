package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.nostr.KeyVaultIdentity;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.util.NostrUtil;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyMaster identity derivation (no relay needed).
 */
class KeyMasterTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void createAndLogin() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.createIdentity("alice@atlanta.com");
        assertNotNull(km.getPubKeyHex());
        assertEquals(64, km.getPubKeyHex().length()); // 32 bytes hex
    }

    @Test
    void deterministicIdentity() {
        KeyMaster km1 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km1.createIdentity("alice@atlanta.com");
        KeyMaster km2 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km2.createIdentity("alice@atlanta.com");
        assertEquals(km1.getPubKeyHex(), km2.getPubKeyHex());
    }

    @Test
    void differentIdentitiesDifferentKeys() {
        KeyMaster alice = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        alice.createIdentity("alice@atlanta.com");
        KeyMaster bob = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        bob.createIdentity("bob@ssh.com");
        assertNotEquals(alice.getPubKeyHex(), bob.getPubKeyHex());
    }

    @Test
    void matchesKeyVaultIdentity() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.createIdentity("alice@atlanta.com");

        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        KeyVaultIdentity kvi = new KeyVaultIdentity(vault, "alice@atlanta.com");
        String expected = NostrUtil.bytesToHex(kvi.getPublicKey().getRawData());

        assertEquals(expected, km.getPubKeyHex());
    }

    // ── ApprovalHandler tests ──────────────────────────────────────────

    @Test
    void approvalHandlerAcceptsNull() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.setApprovalHandler(null); // should not throw
        assertNotNull(km);
    }

    @Test
    void approvalHandlerAcceptsLambda() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.setApprovalHandler((type, detail) -> true); // auto-approve lambda
        assertNotNull(km);
    }

    // ── AvatarDescriptor tests ──────────────────────────────────────────

    @Test
    void avatarDescriptorFromJsonWithLoginXpub() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                  "services": ["ssh", "nostr"]
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals("ws://localhost:7777", d.relay());
        assertTrue(d.loginXpub().startsWith("xpub"));
        assertEquals(List.of("ssh", "nostr"), d.services());
    }

    @Test
    void avatarDescriptorFromJsonWithLegacyPubkey() {
        // Backwards compatibility: "pubkey" field still works
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "pubkey": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                  "services": ["ssh"]
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertTrue(d.loginXpub().startsWith("xpub"));
    }

    @Test
    void avatarDescriptorLoginNpub() {
        // Use a known xpub and verify loginNpub() returns a valid 64-char hex
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        String npub = d.loginNpub();
        assertNotNull(npub);
        assertEquals(64, npub.length());
        // Should be valid hex
        assertDoesNotThrow(() -> NostrUtil.hexToBytes(npub));
    }

    @Test
    void avatarDescriptorRejectsNullRelay() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor(null, "xpub123", List.of()));
    }

    @Test
    void avatarDescriptorRejectsNullLoginXpub() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor("ws://localhost:7777", null, List.of()));
    }

    @Test
    void avatarDescriptorDefaultsServicesToEmptyList() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals(List.of(), d.services());
    }

    // ── Realm derivation tests ──────────────────────────────────────────

    @Test
    void realmXpubIsDeterministic() {
        byte[] seed = new byte[64];
        seed[0] = 42;
        KeyMaster km1 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        KeyMaster km2 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed.clone());
        assertEquals(km1.deriveRealmXpub(0), km2.deriveRealmXpub(0));
    }

    @Test
    void realmXpubFormat() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        String xpub = km.deriveRealmXpub(0);
        assertTrue(xpub.startsWith("xpub"), "realm xpub: " + xpub);
    }

    @Test
    void realmServiceKeyDerivation() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        byte[] sshKey = km.deriveRealmServiceKey(0, "ssh", 0);
        byte[] gpgKey = km.deriveRealmServiceKey(0, "gpg", 0);
        assertNotNull(sshKey);
        assertEquals(32, sshKey.length);
        // Different services produce different keys
        assertFalse(java.util.Arrays.equals(sshKey, gpgKey));
    }

    @Test
    void xpubToNpubProduces64CharHex() {
        // Use a valid xpub (m/0 from well-known seed)
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);
        String xpub = kd.deriveXpub(0);
        String npub = NostrTransport.xpubToNpub(xpub);
        assertEquals(64, npub.length());
    }

    // ── SSH service handler integration tests ────────────────────────────

    @Test
    void sshIdentities_throughKeyMaster_matchesOldBehavior() {
        // Pre-refactor format: {"result": {"identities": [{"key_blob": "...", "comment": "..."}]}}
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault);
        km.createIdentity("alice@atlanta.com");

        // Simulate a service request through the handler
        JsonObject response = invokeSshRequest(km, "request_identities", null);

        // Must have result.identities array
        assertTrue(response.has("result"), "response must have 'result'");
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("identities"), "result must have 'identities'");
        JsonArray identities = result.getAsJsonArray("identities");
        assertEquals(1, identities.size());

        JsonObject identity = identities.get(0).getAsJsonObject();
        assertTrue(identity.has("key_blob"));
        assertTrue(identity.has("comment"));
        assertEquals("alice@atlanta.com", identity.get("comment").getAsString());

        // Verify key_blob matches vault-derived SSH key
        int H = 0x80000000;
        int identityIndex = Bip32KeyDerivator.mangle("alice@atlanta.com") | H;
        int[] sshPath = {44 | H, Protocol.SSH.coinType() | H, identityIndex,
                new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex() | H, 0 | H};
        var pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        byte[] expectedBlob = SshServiceHandler.buildSshEd25519KeyBlob(pubResult.data());
        String expectedB64 = Base64.getEncoder().encodeToString(expectedBlob);
        assertEquals(expectedB64, identity.get("key_blob").getAsString());
    }

    @Test
    void sshSign_throughKeyMaster_matchesOldBehavior() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault);
        km.setApprovalHandler((type, detail) -> true);
        km.createIdentity("alice@atlanta.com");

        // First get the key blob
        JsonObject idResponse = invokeSshRequest(km, "request_identities", null);
        String keyBlobB64 = idResponse.getAsJsonObject("result")
                .getAsJsonArray("identities")
                .get(0).getAsJsonObject()
                .get("key_blob").getAsString();

        // Sign with it
        String dataB64 = Base64.getEncoder().encodeToString("test data".getBytes());
        JsonObject param = new JsonObject();
        param.addProperty("key_blob", keyBlobB64);
        param.addProperty("data", dataB64);
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = invokeSshRequest(km, "sign_request", params);

        // Must have result.signature and result.key_type
        assertTrue(response.has("result"), "response must have 'result'");
        JsonObject result = response.getAsJsonObject("result");
        assertTrue(result.has("signature"));
        assertTrue(result.has("key_type"));
        assertEquals("ssh-ed25519", result.get("key_type").getAsString());

        // Signature should be 64 bytes (Ed25519)
        byte[] sig = Base64.getDecoder().decode(result.get("signature").getAsString());
        assertEquals(64, sig.length);
    }

    @Test
    void sshApproval_bridgesToHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault);

        AtomicBoolean handlerCalled = new AtomicBoolean(false);
        km.setApprovalHandler((type, detail) -> {
            handlerCalled.set(true);
            return false; // deny
        });
        km.createIdentity("alice@atlanta.com");

        // Get the key blob first (request_identities has APPROVE policy, no handler call)
        JsonObject idResponse = invokeSshRequest(km, "request_identities", null);
        String keyBlobB64 = idResponse.getAsJsonObject("result")
                .getAsJsonArray("identities")
                .get(0).getAsJsonObject()
                .get("key_blob").getAsString();

        // Reset flag and try signing (ASK policy → flows through ApprovalHandler)
        handlerCalled.set(false);
        JsonObject param = new JsonObject();
        param.addProperty("key_blob", keyBlobB64);
        param.addProperty("data", Base64.getEncoder().encodeToString("data".getBytes()));
        JsonArray params = new JsonArray();
        params.add(param);

        JsonObject response = invokeSshRequest(km, "sign_request", params);

        assertTrue(handlerCalled.get(), "ApprovalHandler should have been called");
        assertTrue(response.has("error"));
        assertEquals("request denied by user", response.get("error").getAsString());
    }

    /**
     * Invoke the SSH request handler on KeyMaster via the package-private service handler path.
     * Uses reflection to access the private handleServiceRequest method, simulating transport dispatch.
     */
    private static JsonObject invokeSshRequest(KeyMaster km, String method, JsonArray params) {
        try {
            var m = KeyMaster.class.getDeclaredMethod(
                    "handleServiceRequest", String.class, String.class, JsonArray.class);
            m.setAccessible(true);
            return (JsonObject) m.invoke(km, "ssh", method, params);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void deriveServicePubkeyFromXpubConsistency() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);

        // Derive privkey path: 0 / mangle("ssh") / 0
        int protocolIdx = Bip32KeyDerivator.mangle("ssh");
        byte[] privKey = kd.derive(0, protocolIdx, 0);
        byte[] pubKeyFromPriv = NostrTransport.computeSchnorrPubKey(privKey);
        String pubHexFromPriv = NostrUtil.bytesToHex(pubKeyFromPriv);

        // Derive xpub at m/0, then public-only derive to mangle("ssh")/0
        String xpub = kd.deriveXpub(0);
        String pubHexFromXpub = NostrTransport.deriveServicePubkeyFromXpub(xpub, protocolIdx, 0);

        assertEquals(pubHexFromPriv, pubHexFromXpub,
                "Private-derived pubkey must match public-derived pubkey");
    }
}
