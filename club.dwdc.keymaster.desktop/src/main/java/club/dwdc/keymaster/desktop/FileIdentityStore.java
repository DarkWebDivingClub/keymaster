package club.dwdc.keymaster.desktop;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * File-based identity storage for desktop systems.
 *
 * <p>Stores identity-to-pubkey mappings in JSON at
 * {@code $KM_HOME/identities.json} (default: {@code ~/.config/keymaster/identities.json}).
 * The directory is created with mode 0700 and the file with mode 0600.
 */
public class FileIdentityStore {

    private static final Set<PosixFilePermission> DIR_PERMS =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_PERMS =
            PosixFilePermissions.fromString("rw-------");

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Type LIST_TYPE = new TypeToken<List<IdentityEntry>>() {}.getType();

    private final Path identitiesPath;

    /**
     * Identity entry: maps an identity name to its public key.
     */
    public record IdentityEntry(String identity, String pubkey) {}

    /** Create using default path: {@code $KM_HOME/identities.json} or {@code ~/.config/keymaster/identities.json}. */
    public FileIdentityStore() {
        this(defaultBaseDir());
    }

    /** Create using the given base directory (useful for testing with {@code @TempDir}). */
    public FileIdentityStore(Path baseDir) {
        this.identitiesPath = baseDir.resolve("identities.json");
    }

    /**
     * Add or overwrite an identity entry.
     */
    public void add(String identity, String pubkey) {
        List<IdentityEntry> entries = loadEntries();
        entries.removeIf(e -> e.identity().equals(identity));
        entries.add(new IdentityEntry(identity, pubkey));
        saveEntries(entries);
    }

    /**
     * List all stored identity entries.
     */
    public List<IdentityEntry> list() {
        return loadEntries();
    }

    /**
     * Get the entry for the given identity, or {@code null} if not found.
     */
    public IdentityEntry get(String identity) {
        return loadEntries().stream()
                .filter(e -> e.identity().equals(identity))
                .findFirst()
                .orElse(null);
    }

    /**
     * Check whether an identity exists in the store.
     */
    public boolean exists(String identity) {
        return get(identity) != null;
    }

    /**
     * Remove an identity from the store.
     *
     * @return {@code true} if the identity was found and removed
     */
    public boolean remove(String identity) {
        List<IdentityEntry> entries = loadEntries();
        boolean removed = entries.removeIf(e -> e.identity().equals(identity));
        if (removed) {
            saveEntries(entries);
        }
        return removed;
    }

    private List<IdentityEntry> loadEntries() {
        if (!Files.exists(identitiesPath)) {
            return new ArrayList<>();
        }
        try {
            String json = Files.readString(identitiesPath);
            List<IdentityEntry> entries = GSON.fromJson(json, LIST_TYPE);
            return entries != null ? new ArrayList<>(entries) : new ArrayList<>();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read identities", e);
        }
    }

    private void saveEntries(List<IdentityEntry> entries) {
        try {
            Path dir = identitiesPath.getParent();
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
                Files.setPosixFilePermissions(dir, DIR_PERMS);
            }
            Files.writeString(identitiesPath, GSON.toJson(entries));
            Files.setPosixFilePermissions(identitiesPath, FILE_PERMS);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write identities", e);
        }
    }

    private static Path defaultBaseDir() {
        String kmHome = System.getenv("KM_HOME");
        if (kmHome != null && !kmHome.isEmpty()) {
            return Path.of(kmHome);
        }
        return Path.of(System.getProperty("user.home"), ".config", "keymaster");
    }
}
