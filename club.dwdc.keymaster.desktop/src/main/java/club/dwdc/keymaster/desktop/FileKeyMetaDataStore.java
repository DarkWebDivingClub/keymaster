package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.KeyEntry;
import club.dwdc.keymaster.KeyMetaDataStore;
import club.dwdc.keymaster.StoreMigration;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

/**
 * File-backed key metadata store for desktop systems.
 *
 * <p>Stores key entries in {@code $KM_HOME/key-metadata.json} and identity
 * name mappings in {@code $KM_HOME/identity-names.json}. Directories are
 * created with mode 0700, files with mode 0600.
 *
 * <p>Derivation paths are serialized as standard BIP-32 strings,
 * e.g. {@code "m/44'/1238'/624718342'/0'/0'"}.
 *
 * <p>File format version {@value StoreMigration#CURRENT_VERSION} (keymaster
 * 0.9.0): {@code {"version": 2, "keys": [...]}}. A file that is a bare JSON
 * array was written by keymaster 0.8.x or earlier: on first load it is copied
 * to {@code key-metadata.json.pre-0.9.bak}, migrated with
 * {@link StoreMigration}, and rewritten in the new format; the migration log
 * goes to the application log and to {@code key-metadata.migration-0.9.log}.
 * A file that cannot be read or migrated is left untouched and the store
 * fails to open, which stops the daemon with the reason.
 */
public class FileKeyMetaDataStore implements KeyMetaDataStore {

    private static final Set<PosixFilePermission> DIR_PERMS =
            PosixFilePermissions.fromString("rwx------");
    private static final Set<PosixFilePermission> FILE_PERMS =
            PosixFilePermissions.fromString("rw-------");

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .registerTypeHierarchyAdapter(HDPath.class, new HDPathTypeAdapter())
            .create();

    private static final Logger log = LoggerFactory.getLogger(FileKeyMetaDataStore.class);

    static final String BACKUP_SUFFIX = ".pre-0.9.bak";
    static final String MIGRATION_LOG = "key-metadata.migration-0.9.log";

    private static final Type KEY_LIST_TYPE = new TypeToken<List<KeyEntry>>() {}.getType();
    private static final Type NAME_MAP_TYPE = new TypeToken<Map<Integer, String>>() {}.getType();

    private final Path keyMetadataPath;
    private final Path identityNamesPath;

    private final Map<HDPath, KeyEntry> keys;
    private final Map<Integer, String> identityNames;

    /** Create using default path: {@code $KM_HOME} or {@code ~/.config/keymaster}. */
    public FileKeyMetaDataStore() {
        this(defaultBaseDir());
    }

    /** Create using the given base directory (useful for testing with {@code @TempDir}). */
    public FileKeyMetaDataStore(Path baseDir) {
        this.keyMetadataPath = baseDir.resolve("key-metadata.json");
        this.identityNamesPath = baseDir.resolve("identity-names.json");
        this.keys = loadKeys();
        this.identityNames = loadIdentityNames();
    }

    @Override
    public void addIdentity(String identity) {
        int hash = Bip32KeyDerivator.mangle(identity);
        identityNames.put(hash, identity);
        saveIdentityNames();
    }

    @Override
    public String getIdentityName(int mangleHash) {
        return identityNames.get(mangleHash);
    }

    @Override
    public void addKey(KeyEntry entry) {
        keys.put(entry.path(), entry);
        saveKeys();
    }

    @Override
    public void removeKey(HDPath path) {
        if (keys.remove(path) != null) {
            saveKeys();
        }
    }

    @Override
    public KeyEntry getKey(HDPath path) {
        return keys.get(path);
    }

    @Override
    public List<KeyEntry> keysByProtocol(int coinType) {
        return keys.values().stream()
                .filter(e -> e.coinType() == coinType)
                .toList();
    }

    @Override
    public List<KeyEntry> keysByIdentity(int mangleHash) {
        return keys.values().stream()
                .filter(e -> e.identity() == mangleHash)
                .toList();
    }

    @Override
    public List<KeyEntry> allKeys() {
        return List.copyOf(keys.values());
    }

    // --- persistence ---

    private Map<HDPath, KeyEntry> loadKeys() {
        if (!Files.exists(keyMetadataPath)) {
            return new LinkedHashMap<>();
        }
        String json;
        try {
            json = Files.readString(keyMetadataPath);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read key metadata", e);
        }
        JsonElement root;
        try {
            root = json.isBlank() ? null : JsonParser.parseString(json);
        } catch (JsonParseException e) {
            throw new IllegalStateException(keyMetadataPath + " is not valid JSON; left unchanged", e);
        }
        if (root == null || root.isJsonNull()) {
            return new LinkedHashMap<>();
        }
        if (root.isJsonArray()) {
            return migrateLegacy(root);
        }
        if (!root.isJsonObject() || !root.getAsJsonObject().has("version")) {
            throw new IllegalStateException(keyMetadataPath + " has an unknown format; left unchanged");
        }
        JsonObject obj = root.getAsJsonObject();
        int version = obj.get("version").getAsInt();
        if (version != StoreMigration.CURRENT_VERSION) {
            throw new IllegalStateException(keyMetadataPath + " has format version " + version
                    + "; this keymaster reads version " + StoreMigration.CURRENT_VERSION + "; left unchanged");
        }
        return toMap(parseEntries(obj.get("keys")));
    }

    /** A bare array: keymaster 0.8.x. Back up, migrate, rewrite (mission 48.3 step 5). */
    private Map<HDPath, KeyEntry> migrateLegacy(JsonElement array) {
        List<KeyEntry> legacy = parseEntries(array);
        StoreMigration.Result result =
                StoreMigration.migrate(legacy, System.currentTimeMillis() / 1000);

        Path backup = keyMetadataPath.resolveSibling(keyMetadataPath.getFileName() + BACKUP_SUFFIX);
        try {
            if (!Files.exists(backup)) {
                Files.copy(keyMetadataPath, backup, StandardCopyOption.COPY_ATTRIBUTES);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to back up " + keyMetadataPath + "; left unchanged", e);
        }

        Map<HDPath, KeyEntry> migrated = toMap(result.entries());
        log.info("Migrating {} ({} entries) to format version {}; backup {}",
                keyMetadataPath, legacy.size(), StoreMigration.CURRENT_VERSION, backup);
        StringBuilder text = new StringBuilder("# keymaster 0.9.0 store migration, ")
                .append(java.time.Instant.now()).append('\n');
        for (String line : result.log()) {
            log.info("migration: {}", line);
            text.append(line).append('\n');
        }
        saveFile(keyMetadataPath.resolveSibling(MIGRATION_LOG), text.toString());
        writeKeys(migrated.values());
        return migrated;
    }

    private List<KeyEntry> parseEntries(JsonElement array) {
        try {
            List<KeyEntry> entries = GSON.fromJson(array, KEY_LIST_TYPE);
            return entries == null ? List.of() : entries;
        } catch (JsonParseException | IllegalArgumentException | IllegalStateException e) {
            throw new IllegalStateException(keyMetadataPath + " has unreadable entries; left unchanged", e);
        }
    }

    private static LinkedHashMap<HDPath, KeyEntry> toMap(List<KeyEntry> entries) {
        LinkedHashMap<HDPath, KeyEntry> map = new LinkedHashMap<>();
        for (KeyEntry e : entries) {
            map.put(e.path(), e);
        }
        return map;
    }

    private Map<Integer, String> loadIdentityNames() {
        if (!Files.exists(identityNamesPath)) {
            return new LinkedHashMap<>();
        }
        try {
            String json = Files.readString(identityNamesPath);
            Map<Integer, String> map = GSON.fromJson(json, NAME_MAP_TYPE);
            return map != null ? new LinkedHashMap<>(map) : new LinkedHashMap<>();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read identity names", e);
        }
    }

    private void saveKeys() {
        writeKeys(keys.values());
    }

    private void writeKeys(Collection<KeyEntry> entries) {
        JsonObject obj = new JsonObject();
        obj.addProperty("version", StoreMigration.CURRENT_VERSION);
        obj.add("keys", GSON.toJsonTree(new ArrayList<>(entries), KEY_LIST_TYPE));
        saveFile(keyMetadataPath, GSON.toJson(obj));
    }

    private void saveIdentityNames() {
        saveFile(identityNamesPath, GSON.toJson(identityNames, NAME_MAP_TYPE));
    }

    private void saveFile(Path file, String content) {
        try {
            Path dir = file.getParent();
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
                Files.setPosixFilePermissions(dir, DIR_PERMS);
            }
            // Write a sibling and move it into place, so a crash never leaves half a file.
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(tmp, content);
            Files.setPosixFilePermissions(tmp, FILE_PERMS);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write " + file.getFileName(), e);
        }
    }

    private static Path defaultBaseDir() {
        String kmHome = System.getenv("KM_HOME");
        if (kmHome != null && !kmHome.isEmpty()) {
            return Path.of(kmHome);
        }
        return Path.of(System.getProperty("user.home"), ".config", "keymaster");
    }

    // --- Gson TypeAdapter for HDPath <-> BIP-32 string ---

    static class HDPathTypeAdapter extends TypeAdapter<HDPath> {
        @Override
        public void write(JsonWriter out, HDPath path) throws IOException {
            if (path == null) {
                out.nullValue();
                return;
            }
            StringBuilder sb = new StringBuilder("m");
            for (ChildNumber child : path.list()) {
                sb.append('/');
                sb.append(child.num());
                if (child.isHardened()) sb.append('\'');
            }
            out.value(sb.toString());
        }

        @Override
        public HDPath read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            return HDPath.parsePath(in.nextString());
        }
    }
}
