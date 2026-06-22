package club.dwdc.keymaster.daemon;

import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keyvault.core.SeedStore;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

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
