package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Base class for typed service handlers.
 *
 * <p>Provides approval checking infrastructure by scanning {@link ServiceMethod}
 * annotations on the concrete subclass. Each annotated method has a default
 * {@link ApprovalPolicy} that can be overridden at runtime.
 */
public abstract class AbstractServiceHandler {

    protected final KeyVault vault;
    protected final List<KeyEntry> keys;
    private final Map<String, ApprovalPolicy> policyMap;
    private ApprovalUI approvalUI;

    protected AbstractServiceHandler(KeyVault vault, List<KeyEntry> keys) {
        this.vault = vault;
        this.keys = List.copyOf(keys);
        this.policyMap = buildDefaultPolicy();
    }

    /**
     * Check approval for a service method invocation.
     *
     * <p>APPROVE falls through, DENY throws {@link RequestDeniedException},
     * ASK delegates to the {@link ApprovalUI} (null UI = deny).
     *
     * @param method      wire name of the method
     * @param description human-readable description
     * @throws RequestDeniedException if the request is denied
     */
    protected void checkApproval(String method, String description) {
        ApprovalPolicy policy = policyMap.getOrDefault(method, ApprovalPolicy.ASK);
        switch (policy) {
            case APPROVE -> { /* fall through */ }
            case DENY -> throw new RequestDeniedException(method);
            case ASK -> {
                if (approvalUI == null || !approvalUI.ask(method, description)) {
                    throw new RequestDeniedException(method);
                }
            }
        }
    }

    /**
     * Set the approval UI for interactive approval.
     *
     * @param ui approval UI, or {@code null} to deny all ASK requests
     */
    public void setApprovalUI(ApprovalUI ui) {
        this.approvalUI = ui;
    }

    /**
     * Override the approval policy for a specific method.
     *
     * @param method wire name of the method
     * @param policy new policy
     */
    public void setPolicy(String method, ApprovalPolicy policy) {
        policyMap.put(method, policy);
    }

    /**
     * Build the default policy map by scanning {@link ServiceMethod} annotations
     * on the concrete subclass.
     */
    private Map<String, ApprovalPolicy> buildDefaultPolicy() {
        Map<String, ApprovalPolicy> map = new HashMap<>();
        for (Method m : getClass().getDeclaredMethods()) {
            ServiceMethod ann = m.getAnnotation(ServiceMethod.class);
            if (ann != null) {
                map.put(ann.value(), ann.defaultPolicy());
            }
        }
        return map;
    }
}
