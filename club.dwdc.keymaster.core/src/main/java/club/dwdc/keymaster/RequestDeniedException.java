package club.dwdc.keymaster;

/**
 * Thrown when a service request is denied by policy or by the user.
 */
public class RequestDeniedException extends RuntimeException {

    private final String method;

    public RequestDeniedException(String method) {
        super("request denied by user");
        this.method = method;
    }

    /** The wire name of the denied method. */
    public String getMethod() {
        return method;
    }
}
