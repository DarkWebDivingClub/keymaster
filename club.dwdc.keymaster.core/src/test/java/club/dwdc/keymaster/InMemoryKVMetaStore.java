package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A {@link KVMetaStore} in a map, for tests. */
class InMemoryKVMetaStore implements KVMetaStore {

    private final Map<HDPath, AbstractKeyEntry> entries = new LinkedHashMap<>();

    @Override
    public void put(AbstractKeyEntry entry) {
        entries.put(entry.path(), entry);
    }

    @Override
    public void remove(HDPath path) {
        entries.remove(path);
    }

    @Override
    public AbstractKeyEntry get(HDPath path) {
        return entries.get(path);
    }

    @Override
    public List<AbstractKeyEntry> all() {
        return new ArrayList<>(entries.values());
    }

    @Override
    public List<AbstractKeyEntry> byIdentity(String identity) {
        return entries.values().stream().filter(e -> e.identity().equals(identity)).toList();
    }

    @Override
    public <T extends AbstractKeyEntry> List<T> byType(Class<T> type) {
        return entries.values().stream().filter(type::isInstance).map(type::cast).toList();
    }

    @Override
    public List<String> identities() {
        return entries.values().stream().map(AbstractKeyEntry::identity).distinct().toList();
    }
}
