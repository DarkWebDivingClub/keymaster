package club.dwdc.keymaster;

import java.util.Set;
import java.util.function.Predicate;

/**
 * One row of a realm's definition: an identity, and which of its protocols the
 * realm serves. An empty {@code coinTypes} means all protocols of that identity.
 *
 * <p>This is data rather than a lambda on purpose. A realm's definition has to
 * be persistable, displayable, sendable over JSON-RPC, and checkable — none of
 * which a {@link Predicate} allows. The predicate is derived when a realm
 * resolves its handlers and is not kept afterwards.
 *
 * <p>Rows compose by union: {@code [(alice@atlanta.com, all),
 * (alice@home.org, {SSH})]} serves atlanta's SSH, GPG and Nostr keys plus
 * home.org's SSH key only.
 *
 * @param identity  the identity this row selects
 * @param coinTypes protocol coin types to serve, or empty for all
 */
public record IdentitySelection(Identity identity, Set<Integer> coinTypes) {

    public IdentitySelection {
        if (identity == null) {
            throw new IllegalArgumentException("selection needs an identity");
        }
        coinTypes = coinTypes == null ? Set.of() : Set.copyOf(coinTypes);
    }

    /** All protocols of the given identity. */
    public IdentitySelection(Identity identity) {
        this(identity, Set.of());
    }

    /**
     * The key filter this row expresses. {@link Identity#mangled()} is hoisted
     * out of the lambda, so the hash is computed once per row rather than once
     * per key tested.
     */
    public Predicate<KeyEntry> toPredicate() {
        final int mangled = identity.mangled();
        final Set<Integer> protocols = coinTypes;
        return k -> k.identity() == mangled
                && (protocols.isEmpty() || protocols.contains(k.coinType()));
    }
}
