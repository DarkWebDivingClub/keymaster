package club.dwdc.keymaster;

/**
 * Bridges the existing {@link ApprovalHandler} interface to {@link ApprovalUI}.
 *
 * <p>Delegates {@link ApprovalUI#ask} calls to {@link ApprovalHandler#approve},
 * mapping the method wire name to a dotted request type.
 */
public class ApprovalHandlerAdapter implements ApprovalUI {

    private final ApprovalHandler handler;
    private final String serviceType;

    /**
     * @param handler     the existing approval handler
     * @param serviceType service prefix for request type (e.g. "ssh")
     */
    public ApprovalHandlerAdapter(ApprovalHandler handler, String serviceType) {
        this.handler = handler;
        this.serviceType = serviceType;
    }

    @Override
    public boolean ask(String method, String description) {
        String requestType = serviceType + "." + method;
        return handler.approve(requestType, description);
    }
}
