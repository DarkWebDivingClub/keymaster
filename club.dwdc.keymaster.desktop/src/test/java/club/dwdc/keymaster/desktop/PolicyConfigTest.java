package club.dwdc.keymaster.desktop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PolicyConfigTest {

    @TempDir
    Path tempDir;

    @Test
    void defaultSignRequestIsPrompt() {
        // Default: ssh.sign_request = prompt → delegates to handler
        var called = new boolean[]{false};
        PolicyConfig config = new PolicyConfig(null, (type, detail) -> {
            called[0] = true;
            return true;
        });
        assertTrue(config.approve("ssh.sign_request", "test"));
        assertTrue(called[0], "prompt handler should have been called");
    }

    @Test
    void defaultIdentityRequestIsAuto() {
        // Default: ssh.request_identities = auto → always true, handler NOT called
        var called = new boolean[]{false};
        PolicyConfig config = new PolicyConfig(null, (type, detail) -> {
            called[0] = true;
            return false;
        });
        assertTrue(config.approve("ssh.request_identities", "test"));
        assertFalse(called[0], "prompt handler should not be called for auto");
    }

    @Test
    void loadFromConfigFile() throws Exception {
        Path configFile = tempDir.resolve("policy.conf");
        Files.writeString(configFile, """
                # Override sign to auto
                ssh.sign_request = auto
                gpg.sign_request = deny
                """);

        PolicyConfig config = new PolicyConfig(configFile, (type, detail) -> {
            fail("prompt handler should not be called");
            return false;
        });
        assertTrue(config.approve("ssh.sign_request", "test"));
        assertFalse(config.approve("gpg.sign_request", "test"));
    }

    @Test
    void unknownTypeDefaultsToPrompt() {
        var called = new boolean[]{false};
        PolicyConfig config = new PolicyConfig(null, (type, detail) -> {
            called[0] = true;
            return true;
        });
        assertTrue(config.approve("custom.unknown_method", "test"));
        assertTrue(called[0]);
    }

    @Test
    void denyReturnsFalse() {
        Path configFile = tempDir.resolve("policy.conf");
        try {
            Files.writeString(configFile, "ssh.sign_request = deny\n");
        } catch (Exception e) {
            fail("Failed to write config: " + e.getMessage());
        }

        PolicyConfig config = new PolicyConfig(configFile, (type, detail) -> true);
        assertFalse(config.approve("ssh.sign_request", "test"));
    }

    @Test
    void autoReturnsTrue() {
        PolicyConfig config = new PolicyConfig(null, (type, detail) -> false);
        // ssh.request_identities defaults to auto
        assertTrue(config.approve("ssh.request_identities", "test"));
    }

    @Test
    void promptDelegatesToHandler() {
        PolicyConfig config = new PolicyConfig(null, (type, detail) -> false);
        // ssh.sign_request defaults to prompt → delegates → handler returns false
        assertFalse(config.approve("ssh.sign_request", "test"));
    }
}
