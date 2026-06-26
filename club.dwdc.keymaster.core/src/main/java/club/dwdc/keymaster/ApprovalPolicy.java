package club.dwdc.keymaster;

/**
 * Policy for handling service method approval.
 */
public enum ApprovalPolicy {
    /** Automatically approve — no user interaction needed. */
    APPROVE,
    /** Automatically deny — request is rejected. */
    DENY,
    /** Ask the user via {@link ApprovalUI}. */
    ASK
}
