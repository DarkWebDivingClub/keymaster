package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.KeyEntry;
import club.dwdc.keymaster.KeyMetaDataStore;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * e.g. {@code "m/44'/1238'/624718342'/65536'/0'"}.
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
        try {
            String json = Files.readString(keyMetadataPath);
            List<KeyEntry> entries = GSON.fromJson(json, KEY_LIST_TYPE);
            if (entries == null) return new LinkedHashMap<>();
            LinkedHashMap<HDPath, KeyEntry> map = new LinkedHashMap<>();
            for (KeyEntry e : entries) map.put(e.path(), e);
            return map;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read key metadata", e);
        }
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
        saveFile(keyMetadataPath, GSON.toJson(new ArrayList<>(keys.values()), KEY_LIST_TYPE));
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
            Files.writeString(file, content);
            Files.setPosixFilePermissions(file, FILE_PERMS);
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
