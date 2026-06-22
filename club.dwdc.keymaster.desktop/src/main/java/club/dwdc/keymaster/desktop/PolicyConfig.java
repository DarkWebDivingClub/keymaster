package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.ApprovalHandler;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Policy-based approval handler.
 *
 * <p>Reads a policy configuration file to decide how each request type is handled.
 * Each line is {@code key = value} where value is one of:
 * <ul>
 *   <li>{@code auto} — always approve</li>
 *   <li>{@code deny} — always deny</li>
 *   <li>{@code prompt} — delegate to the prompt handler</li>
 * </ul>
 *
 * <p>Lines starting with {@code #} are comments. Unknown request types default
 * to {@code prompt}. The default prompt handler is {@link KDialogApprovalHandler}.
 *
 * <p>Default policies:
 * <pre>
 * ssh.sign_request = prompt
 * gpg.sign_request = prompt
 * ssh.request_identities = auto
 * gpg.request_identities = auto
 * gpg.get_public_cert = auto
 * </pre>
 */
public class PolicyConfig implements ApprovalHandler {

    private final Map<String, String> policies = new HashMap<>();
    private final ApprovalHandler promptHandler;

    /**
     * Create a PolicyConfig with defaults and a prompt handler for interactive approval.
     *
     * @param configPath    path to the policy.conf file (may not exist — defaults are used)
     * @param promptHandler handler invoked when policy is {@code prompt}
     */
    public PolicyConfig(Path configPath, ApprovalHandler promptHandler) {
        this.promptHandler = promptHandler;

        // Defaults
        policies.put("ssh.sign_request", "prompt");
        policies.put("gpg.sign_request", "prompt");
        policies.put("ssh.request_identities", "auto");
        policies.put("gpg.request_identities", "auto");
        policies.put("gpg.get_public_cert", "auto");

        if (configPath != null && Files.exists(configPath)) {
            loadConfig(configPath);
        }
    }

    @Override
    public boolean approve(String requestType, String detail) {
        String action = policies.getOrDefault(requestType, "prompt");
        return switch (action) {
            case "auto" -> true;
            case "deny" -> false;
            default -> promptHandler.approve(requestType, detail);
        };
    }

    private void loadConfig(Path configPath) {
        try {
            for (String line : Files.readAllLines(configPath)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                int eq = trimmed.indexOf('=');
                if (eq > 0) {
                    String key = trimmed.substring(0, eq).trim();
                    String value = trimmed.substring(eq + 1).trim();
                    policies.put(key, value);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read policy config", e);
        }
    }
}
