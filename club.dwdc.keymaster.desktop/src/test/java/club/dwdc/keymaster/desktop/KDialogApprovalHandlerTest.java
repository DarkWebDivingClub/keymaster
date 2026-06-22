package club.dwdc.keymaster.desktop;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class KDialogApprovalHandlerTest {

    @Test
    void buildProcessConstructsCorrectCommand() {
        KDialogApprovalHandler handler = new KDialogApprovalHandler();
        ProcessBuilder pb = handler.buildProcess("ssh.sign_request", "SSH signing request for alice@atlanta.com");
        List<String> cmd = pb.command();

        assertEquals("kdialog", cmd.get(0));
        assertEquals("--yesno", cmd.get(1));
        assertEquals("SSH signing request for alice@atlanta.com", cmd.get(2));
        assertEquals("--title", cmd.get(3));
        assertEquals("KeyMaster: ssh.sign_request", cmd.get(4));
        assertEquals("--yes-label", cmd.get(5));
        assertEquals("Approve", cmd.get(6));
        assertEquals("--no-label", cmd.get(7));
        assertEquals("Deny", cmd.get(8));
    }

    @Test
    void exitZeroApproves() {
        // Use a handler that overrides buildProcess to use /usr/bin/true
        KDialogApprovalHandler handler = new KDialogApprovalHandler() {
            @Override
            ProcessBuilder buildProcess(String requestType, String detail) {
                return new ProcessBuilder("/usr/bin/true");
            }
        };
        assertTrue(handler.approve("ssh.sign_request", "test"));
    }

    @Test
    void exitNonZeroDenies() {
        KDialogApprovalHandler handler = new KDialogApprovalHandler() {
            @Override
            ProcessBuilder buildProcess(String requestType, String detail) {
                return new ProcessBuilder("/usr/bin/false");
            }
        };
        assertFalse(handler.approve("ssh.sign_request", "test"));
    }

    @Test
    void programNotFoundDenies() {
        KDialogApprovalHandler handler = new KDialogApprovalHandler() {
            @Override
            ProcessBuilder buildProcess(String requestType, String detail) {
                return new ProcessBuilder("/nonexistent/program");
            }
        };
        assertFalse(handler.approve("ssh.sign_request", "test"));
    }
}
