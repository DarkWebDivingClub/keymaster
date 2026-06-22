package club.dwdc.keymaster;

/**
 * Callback for approving or denying incoming service requests.
 *
 * <p>Implementations may prompt the user (GUI popup, terminal prompt),
 * apply policy rules, or auto-approve for CI/test scenarios.
 */
@FunctionalInterface
public interface ApprovalHandler {

    /**
     * Decide whether to approve a service request.
     *
     * @param requestType dotted identifier, e.g. {@code "ssh.sign_request"}
     * @param detail      human-readable description for display
     * @return {@code true} to approve, {@code false} to deny
     */
    boolean approve(String requestType, String detail);
}
