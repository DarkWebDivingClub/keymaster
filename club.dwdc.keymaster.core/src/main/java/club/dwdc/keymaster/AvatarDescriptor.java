package club.dwdc.keymaster;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.DeterministicKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Describes an Avatar endpoint: its relay URL, login xpub (BIP-32 extended
 * public key), and the services it supports.
 *
 * @param relay      Nostr relay WebSocket URL (e.g. "ws://localhost:7777")
 * @param loginXpub  Avatar's BIP-32 extended public key (Base58Check "xpub...")
 * @param services   service identifiers the Avatar supports (e.g. "ssh", "nostr")
 */
public record AvatarDescriptor(
        String relay,
        String loginXpub,
        List<String> services
) {
    private static final Gson GSON = new GsonBuilder().create();

    public AvatarDescriptor {
        if (relay == null || relay.isBlank()) {
            throw new IllegalArgumentException("relay must not be null or blank");
        }
        if (loginXpub == null || loginXpub.isBlank()) {
            throw new IllegalArgumentException("loginXpub must not be null or blank");
        }
        if (services == null) {
            services = List.of();
        } else {
            services = List.copyOf(services);
        }
    }

    /**
     * Derive the login pubkey (x-only Schnorr public key hex) from the login xpub.
     * This is used for addressing Nostr events to the Avatar.
     *
     * @return 64-character hex string of the x-only public key
     */
    public String loginPubkey() {
        DeterministicKey key = DeterministicKey.deserializeB58(loginXpub, BitcoinNetwork.MAINNET);
        // Compressed SEC1 key is 33 bytes; x-only is bytes [1..33]
        byte[] compressed = key.getPubKey();
        byte[] xOnly = new byte[32];
        System.arraycopy(compressed, 1, xOnly, 0, 32);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : xOnly) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * Deserialize an {@code AvatarDescriptor} from a JSON string.
     * Supports both new "login_xpub" field and legacy "pubkey" field.
     *
     * @param json JSON object with "relay", "login_xpub" (or "pubkey"), and optional "services" fields
     * @return parsed descriptor
     */
    public static AvatarDescriptor fromJson(String json) {
        Raw raw = GSON.fromJson(json, Raw.class);
        String xpub = raw.login_xpub != null ? raw.login_xpub : raw.pubkey;
        return new AvatarDescriptor(
                raw.relay,
                xpub,
                raw.services != null ? raw.services : List.of()
        );
    }

    /**
     * Read an {@code AvatarDescriptor} from a JSON file.
     *
     * @param path path to a JSON file
     * @return parsed descriptor
     * @throws IOException if the file cannot be read
     */
    public static AvatarDescriptor fromFile(Path path) throws IOException {
        return fromJson(Files.readString(path));
    }

    /** Internal deserialization target — allows null fields for validation in the record constructor. */
    private static class Raw {
        String relay;
        String login_xpub;
        String pubkey;  // legacy field name
        List<String> services;
    }
}
