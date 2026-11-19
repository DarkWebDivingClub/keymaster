package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;

/**
 * An identity — the clear-text string is the identity.
 *
 * <p>{@link #mangled()} is the level-3 path component of every key belonging to
 * this identity. It is a pure function of {@link #name()}, derived on demand and
 * never stored, so the two can never disagree.
 *
 * <p>The name is kept exactly as given. {@code mangle()} hashes the raw UTF-8
 * bytes and the identity key trees are frozen (see {@code doc/key-derivation.md}),
 * so normalising the string here — lowercase, trim, Unicode NFC — would relocate
 * every existing key.
 *
 * @param name identity identifier in email form, e.g. {@code alice@atlanta.com}
 */
public record Identity(String name) {

    public Identity {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("identity must not be blank");
        }
    }

    /**
     * Level-3 path component for this identity: {@code mangle(name)}, 31 bits,
     * without the hardened bit.
     */
    public int mangled() {
        return Bip32KeyDerivator.mangle(name);
    }

    /**
     * The local part of the identity, used as a realm's default name.
     * Returns the whole string when there is no {@code @}.
     */
    public String localPart() {
        int at = name.indexOf('@');
        return at > 0 ? name.substring(0, at) : name;
    }

    @Override
    public String toString() {
        return name;
    }
}
