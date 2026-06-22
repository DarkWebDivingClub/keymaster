package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.ApprovalHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

/**
 * Approval handler that spawns {@code kdialog} for interactive approval prompts.
 *
 * <p>Invokes: {@code kdialog --yesno "<detail>" --title "KeyMaster: <requestType>"
 * --yes-label "Approve" --no-label "Deny"}
 *
 * <p>Exit code 0 means approve; any non-zero exit code means deny.
 * A 60-second timeout is enforced; timeout or error results in denial.
 */
public class KDialogApprovalHandler implements ApprovalHandler {

    private static final Logger log = LoggerFactory.getLogger(KDialogApprovalHandler.class);
    private static final long TIMEOUT_SECONDS = 60;

    @Override
    public boolean approve(String requestType, String detail) {
        try {
            ProcessBuilder pb = buildProcess(requestType, detail);
            pb.inheritIO();
            Process process = pb.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                log.warn("kdialog timed out after {}s, denying request: {}", TIMEOUT_SECONDS, requestType);
                process.destroyForcibly();
                return false;
            }
            return process.exitValue() == 0;
        } catch (Exception e) {
            log.warn("kdialog failed for {}: {}", requestType, e.getMessage());
            return false;
        }
    }

    /**
     * Build the ProcessBuilder for the kdialog command.
     * Package-private for testing.
     */
    ProcessBuilder buildProcess(String requestType, String detail) {
        return new ProcessBuilder(
                "kdialog",
                "--yesno", detail,
                "--title", "KeyMaster: " + requestType,
                "--yes-label", "Approve",
                "--no-label", "Deny");
    }
}
