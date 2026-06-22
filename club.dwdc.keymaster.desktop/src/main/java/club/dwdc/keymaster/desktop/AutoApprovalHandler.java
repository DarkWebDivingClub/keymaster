package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.ApprovalHandler;

/**
 * Approval handler that automatically approves all requests.
 *
 * <p>Used with {@code --policy auto} for CI/test environments
 * where no user interaction is available.
 */
public class AutoApprovalHandler implements ApprovalHandler {

    @Override
    public boolean approve(String requestType, String detail) {
        return true;
    }
}
