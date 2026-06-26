package club.dwdc.keymaster;

/**
 * User interface for interactive approval of service requests.
 */
public interface ApprovalUI {

    /**
     * Ask the user whether to approve a service request.
     *
     * @param method      the wire name of the service method (e.g. "sign_request")
     * @param description human-readable description of the request
     * @return {@code true} to approve, {@code false} to deny
     */
    boolean ask(String method, String description);
}
