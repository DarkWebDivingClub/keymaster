package club.dwdc.keymaster.desktop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AutoApprovalHandlerTest {

    @Test
    void alwaysReturnsTrue() {
        AutoApprovalHandler handler = new AutoApprovalHandler();
        assertTrue(handler.approve("ssh.sign_request", "Sign test data"));
        assertTrue(handler.approve("gpg.sign_request", "GPG sign"));
        assertTrue(handler.approve("unknown.method", "Whatever"));
    }
}
