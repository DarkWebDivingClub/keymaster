package club.dwdc.keymaster;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method as a service handler method with a wire name and default approval policy.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ServiceMethod {

    /** Wire name used for dispatch (e.g. "request_identities", "sign_request"). */
    String value();

    /** Default approval policy for this method. */
    ApprovalPolicy defaultPolicy() default ApprovalPolicy.ASK;
}
