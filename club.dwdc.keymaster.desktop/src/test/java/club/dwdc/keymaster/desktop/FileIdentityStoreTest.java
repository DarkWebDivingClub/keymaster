package club.dwdc.keymaster.desktop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FileIdentityStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void addAndGetRoundTrip() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        store.add("alice@atlanta.com", "fa78dd12");

        FileIdentityStore.IdentityEntry entry = store.get("alice@atlanta.com");
        assertNotNull(entry);
        assertEquals("alice@atlanta.com", entry.identity());
        assertEquals("fa78dd12", entry.pubkey());
    }

    @Test
    void listMultiple() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        store.add("alice@atlanta.com", "fa78dd12");
        store.add("bob@boston.org", "ef56gh78");

        List<FileIdentityStore.IdentityEntry> entries = store.list();
        assertEquals(2, entries.size());
    }

    @Test
    void overwriteExisting() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        store.add("alice@atlanta.com", "oldkey");
        store.add("alice@atlanta.com", "newkey");

        List<FileIdentityStore.IdentityEntry> entries = store.list();
        assertEquals(1, entries.size());
        assertEquals("newkey", store.get("alice@atlanta.com").pubkey());
    }

    @Test
    void removeExisting() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        store.add("alice@atlanta.com", "fa78dd12");
        assertTrue(store.remove("alice@atlanta.com"));
        assertNull(store.get("alice@atlanta.com"));
    }

    @Test
    void removeNonExistent() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        assertFalse(store.remove("nobody@nowhere.com"));
    }

    @Test
    void existsReturnsCorrectly() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        assertFalse(store.exists("alice@atlanta.com"));
        store.add("alice@atlanta.com", "fa78dd12");
        assertTrue(store.exists("alice@atlanta.com"));
    }

    @Test
    void emptyListWhenNoFile() {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        List<FileIdentityStore.IdentityEntry> entries = store.list();
        assertTrue(entries.isEmpty());
    }

    @Test
    void filePermissions0600() throws Exception {
        FileIdentityStore store = new FileIdentityStore(tempDir);
        store.add("alice@atlanta.com", "fa78dd12");

        Path file = tempDir.resolve("identities.json");
        assertTrue(Files.exists(file));
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
        assertEquals(
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                perms);
    }
}
