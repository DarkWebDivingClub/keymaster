package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;

/**
 * OpenPGP key metadata entry.
 */
public class GPGKeyEntry extends AbstractKeyEntry {

    private final String name;
    private final String email;
    private final long creationTime;

    public GPGKeyEntry(HDPath path, String identity, String name, String email, long creationTime) {
        super(path, identity);
        this.name = name;
        this.email = email;
        this.creationTime = creationTime;
    }

    public String name() { return name; }
    public String email() { return email; }
    public long creationTime() { return creationTime; }

    @Override
    public KeyEntry toKeyEntry() {
        return new KeyEntry(path(), Map.of(
                "label", identity() + " / " + (role() == 0 ? "certification" : "signing"),
                "key_type", "ed25519",
                "identity", identity(),
                "creation_time", String.valueOf(creationTime),
                "pgp_name", name,
                "pgp_email", email));
    }
}
