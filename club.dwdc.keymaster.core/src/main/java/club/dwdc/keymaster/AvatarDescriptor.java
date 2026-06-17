package club.dwdc.keymaster;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Describes an Avatar endpoint: its relay URL, transport public key,
 * and the services it supports.
 *
 * @param relay    Nostr relay WebSocket URL (e.g. "ws://localhost:7777")
 * @param pubkey   Avatar's Schnorr transport public key (64 hex characters)
 * @param services service identifiers the Avatar supports (e.g. "ssh", "nostr")
 */
public record AvatarDescriptor(
        String relay,
        String pubkey,
        List<String> services
) {
    private static final Gson GSON = new GsonBuilder().create();

    public AvatarDescriptor {
        if (relay == null || relay.isBlank()) {
            throw new IllegalArgumentException("relay must not be null or blank");
        }
        if (pubkey == null || pubkey.isBlank()) {
            throw new IllegalArgumentException("pubkey must not be null or blank");
        }
        if (services == null) {
            services = List.of();
        } else {
            services = List.copyOf(services);
        }
    }

    /**
     * Deserialize an {@code AvatarDescriptor} from a JSON string.
     *
     * @param json JSON object with "relay", "pubkey", and optional "services" fields
     * @return parsed descriptor
     */
    public static AvatarDescriptor fromJson(String json) {
        Raw raw = GSON.fromJson(json, Raw.class);
        return new AvatarDescriptor(
                raw.relay,
                raw.pubkey,
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
        String pubkey;
        List<String> services;
    }
}
