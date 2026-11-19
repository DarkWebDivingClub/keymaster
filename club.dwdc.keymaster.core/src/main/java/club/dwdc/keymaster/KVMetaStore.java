package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Typed key metadata store used by the Android UI layer.
 * Provides CRUD operations on {@link AbstractKeyEntry} instances.
 */
public interface KVMetaStore {

    void put(AbstractKeyEntry entry);

    void remove(HDPath path);

    AbstractKeyEntry get(HDPath path);

    List<AbstractKeyEntry> all();

    List<AbstractKeyEntry> byIdentity(String identity);

    <T extends AbstractKeyEntry> List<T> byType(Class<T> type);

    List<String> identities();

    /** Remove all entries for a given identity string. */
    default void removeByIdentity(String identity) {
        byIdentity(identity).stream()
                .map(AbstractKeyEntry::path)
                .collect(Collectors.toList())
                .forEach(this::remove);
    }
}
