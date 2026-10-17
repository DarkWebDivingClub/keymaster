package club.dwdc.keymaster.daemon;

import club.dwdc.keymaster.Identity;
import club.dwdc.keymaster.IdentitySelection;
import club.dwdc.keymaster.desktop.AutoApprovalHandler;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keymaster.desktop.PolicyConfig;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.SeedStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DaemonControllerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @TempDir
    Path tempDir;

    private DaemonController controller;

    @BeforeEach
    void setUp() {
        SeedStore seedStore = new StubSeedStore(true);
        FileIdentityStore identityStore = new FileIdentityStore(tempDir);
        controller = new DaemonController(seedStore, identityStore, tempDir);
    }

    @Test
    void identityCreateStoresEntry() {
        JsonObject params = new JsonObject();
        params.addProperty("identity", "alice@atlanta.com");

        JsonObject result = controller.handle("identity.create", params);
        assertFalse(result.has("error"), "Should not have error: " + result);
        assertEquals("alice@atlanta.com", result.get("identity").getAsString());
        assertEquals(64, result.get("pubkey").getAsString().length());
    }

    @Test
    void identityListReturnsEntries() {
        // Create two identities
        JsonObject p1 = new JsonObject();
        p1.addProperty("identity", "alice@atlanta.com");
        controller.handle("identity.create", p1);

        JsonObject p2 = new JsonObject();
        p2.addProperty("identity", "bob@boston.org");
        controller.handle("identity.create", p2);

        JsonObject result = controller.handle("identity.list", new JsonObject());
        assertFalse(result.has("error"));
        assertEquals(2, result.getAsJsonArray("identities").size());
    }

    @Test
    void identityShowUnknownReturnsError() {
        JsonObject params = new JsonObject();
        params.addProperty("identity", "nobody@nowhere.com");

        JsonObject result = controller.handle("identity.show", params);
        assertTrue(result.has("error"));
        assertTrue(result.get("error").getAsString().contains("not found"));
    }

    @Test
    void identityShowReturnsEntry() {
        JsonObject create = new JsonObject();
        create.addProperty("identity", "alice@atlanta.com");
        controller.handle("identity.create", create);

        JsonObject params = new JsonObject();
        params.addProperty("identity", "alice@atlanta.com");
        JsonObject result = controller.handle("identity.show", params);

        assertFalse(result.has("error"));
        assertEquals("alice@atlanta.com", result.get("identity").getAsString());
        assertNotNull(result.get("pubkey").getAsString());
    }

    @Test
    void sessionStatusWhenNotAttached() {
        JsonObject result = controller.handle("session.status", new JsonObject());
        assertFalse(result.has("error"));
        assertFalse(result.get("attached").getAsBoolean());
    }

    @Test
    void sessionDetachWhenNotAttachedReturnsOk() {
        JsonObject result = controller.handle("session.detach", new JsonObject());
        assertFalse(result.has("error"));
        assertEquals("ok", result.get("status").getAsString());
    }

    @Test
    void sessionAttachWithoutDescriptorReturnsError() {
        JsonObject params = new JsonObject();
        params.addProperty("identity", "alice@atlanta.com");
        // missing descriptor

        JsonObject result = controller.handle("session.attach", params);
        assertTrue(result.has("error"));
    }

    @Test
    void unknownMethodReturnsError() {
        JsonObject result = controller.handle("bogus.method", new JsonObject());
        assertTrue(result.has("error"));
        assertTrue(result.get("error").getAsString().contains("unknown method"));
    }

    @Test
    void identityCreateWithoutSeedReturnsError() {
        SeedStore noSeed = new StubSeedStore(false);
        FileIdentityStore identityStore = new FileIdentityStore(tempDir);
        DaemonController ctrl = new DaemonController(noSeed, identityStore, tempDir);

        JsonObject params = new JsonObject();
        params.addProperty("identity", "alice@atlanta.com");

        JsonObject result = ctrl.handle("identity.create", params);
        assertTrue(result.has("error"));
        assertTrue(result.get("error").getAsString().contains("No seed found"));
    }


    // ── parseSelections (41/F12) ──────────────────────────────────────────
    //
    // The realm's definition arrives as JSON, so this is the one place where a
    // selection can be malformed. Every rejection here becomes one RPC error;
    // every acceptance becomes a key filter.

    private static final Identity ALICE = new Identity("alice@atlanta.com");

    @Test
    void omittedIdentitiesYieldThePrimaryAlone() {
        var selections = controller.parseSelections(new JsonObject(), ALICE);

        assertEquals(List.of(new IdentitySelection(ALICE)), selections);
        assertTrue(selections.get(0).coinTypes().isEmpty(), "all protocols");
    }

    @Test
    void aPlainStringEntryIsAnUnfilteredSelection() {
        var selections = controller.parseSelections(
                identities(primitives("alice@home.org")), ALICE);

        assertEquals(2, selections.size());
        assertEquals("alice@home.org", selections.get(1).identity().name());
        assertTrue(selections.get(1).coinTypes().isEmpty());
    }

    @Test
    void anObjectEntryCarriesItsProtocolFilter() {
        var selections = controller.parseSelections(
                identities(filtered("alice@home.org", "ssh", "gpg")), ALICE);

        assertEquals(2, selections.size());
        assertEquals(Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                selections.get(1).coinTypes());
    }

    @Test
    void openpgpAndGpgNameTheSameProtocol() {
        var selections = controller.parseSelections(
                identities(filtered("alice@home.org", "openpgp")), ALICE);

        assertEquals(Set.of(Protocol.OPENPGP.coinType()), selections.get(1).coinTypes());
    }

    @Test
    void thePrimaryIsNeverSelectedTwice() {
        // The GUI sends the whole list including the identity Attach was
        // pressed on; a duplicate row would double every key it serves.
        var selections = controller.parseSelections(
                identities(primitives("alice@atlanta.com", "alice@home.org")), ALICE);

        assertEquals(List.of("alice@atlanta.com", "alice@home.org"),
                selections.stream().map(s -> s.identity().name()).toList());
    }

    @Test
    void anUnknownProtocolIsRejected() {
        assertNull(controller.parseSelections(
                        identities(filtered("alice@home.org", "x509")), ALICE),
                "a protocol we cannot serve must fail loudly, not be dropped");
    }

    @Test
    void aBlankIdentityIsRejected() {
        assertNull(controller.parseSelections(identities(primitives("  ")), ALICE));
    }

    @Test
    void anEntryThatIsNeitherStringNorObjectIsRejected() {
        assertNull(controller.parseSelections(identities(new JsonArray()), ALICE));
    }

    @Test
    void anObjectEntryWithoutAnIdentityIsRejected() {
        var entry = new JsonObject();
        var protocols = new JsonArray();
        protocols.add("ssh");
        entry.add("protocols", protocols);

        assertNull(controller.parseSelections(identities(entry), ALICE));
    }

    @Test
    void anIdentitiesFieldThatIsNotAnArrayIsIgnored() {
        var params = new JsonObject();
        params.addProperty("identities", "alice@home.org");

        assertEquals(1, controller.parseSelections(params, ALICE).size(),
                "falls back to the primary alone");
    }

    @Test
    void aMalformedSelectionSurfacesAsAnAttachError() throws Exception {
        // The RPC path: the parse must fail before anything touches a relay.
        Path descriptor = tempDir.resolve("avatar.json");
        Files.writeString(descriptor, """
                {"relay":"ws://127.0.0.1:1",
                 "login_xpub":"xpub6CUGRUonZSQ4TWtTMmzXdrXDtyPWKiKbbqnWxx2qaGvxZ2x",
                 "services":["ssh"]}""");

        var params = identities(filtered("alice@home.org", "x509"));
        params.addProperty("descriptor", descriptor.toString());
        params.addProperty("identity", "alice@atlanta.com");

        JsonObject result = controller.handle("session.attach", params);

        assertTrue(result.has("error"), "expected an error, got: " + result);
        assertTrue(result.get("error").getAsString().contains("'identities' entries"),
                result.get("error").getAsString());
    }

    // ── the approval-handler default (41/F12) ─────────────────────────────

    @Test
    void anOmittedPolicyOnAFreshControllerMeansInteractive() {
        // A null handler denies every ASK method instead of prompting, so
        // "attach without --policy" must install the interactive default.
        var ctrl = controller.controller(null);

        assertNotNull(ctrl.approvalHandler(), "no handler means every request is denied");
        assertInstanceOf(PolicyConfig.class, ctrl.approvalHandler());
    }

    @Test
    void anAutoPolicyAutoApproves() {
        assertInstanceOf(AutoApprovalHandler.class,
                controller.controller("auto").approvalHandler());
    }

    @Test
    void anOmittedPolicyLeavesAnEstablishedPolicyAlone() {
        controller.controller("auto");

        assertInstanceOf(AutoApprovalHandler.class,
                controller.controller(null).approvalHandler(),
                "a second attach without --policy must not silently re-prompt");
    }

    @Test
    void anExplicitPolicyReplacesAutoApproval() {
        controller.controller("auto");

        assertInstanceOf(PolicyConfig.class, controller.controller("ask").approvalHandler());
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static JsonObject identities(JsonElement... entries) {
        var array = new JsonArray();
        for (JsonElement entry : entries) {
            array.add(entry);
        }
        var params = new JsonObject();
        params.add("identities", array);
        return params;
    }

    private static JsonElement[] primitives(String... names) {
        var out = new JsonElement[names.length];
        for (int i = 0; i < names.length; i++) {
            out[i] = new JsonPrimitive(names[i]);
        }
        return out;
    }

    private static JsonObject filtered(String name, String... protocols) {
        var entry = new JsonObject();
        entry.addProperty("identity", name);
        var array = new JsonArray();
        for (String protocol : protocols) {
            array.add(protocol);
        }
        entry.add("protocols", array);
        return entry;
    }

    /**
     * Stub SeedStore for testing without filesystem seed.
     */
    private static class StubSeedStore implements SeedStore {
        private final boolean hasSeed;

        StubSeedStore(boolean hasSeed) {
            this.hasSeed = hasSeed;
        }

        @Override
        public boolean exists() {
            return hasSeed;
        }

        @Override
        public void store(String mnemonic, String passphrase) {
            // no-op
        }

        @Override
        public String getMnemonic() {
            return TEST_MNEMONIC;
        }

        @Override
        public String getPassphrase() {
            return "";
        }

        @Override
        public void delete() {
            // no-op
        }
    }
}
