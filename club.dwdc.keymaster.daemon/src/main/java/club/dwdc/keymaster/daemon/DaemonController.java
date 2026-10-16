package club.dwdc.keymaster.daemon;

import club.dwdc.keymaster.ApprovalHandler;
import club.dwdc.keymaster.AvatarDescriptor;
import club.dwdc.keymaster.Identity;
import club.dwdc.keymaster.IdentitySelection;
import club.dwdc.keymaster.KeyMaster;
import club.dwdc.keymaster.KeyMasterController;
import club.dwdc.keymaster.Realm;
import club.dwdc.keymaster.desktop.AutoApprovalHandler;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keymaster.desktop.FileKeyMetaDataStore;
import club.dwdc.keymaster.desktop.KDialogApprovalHandler;
import club.dwdc.keymaster.desktop.PolicyConfig;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.SeedStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Business logic for the KeyMaster daemon — implements JSON-RPC method dispatch.
 *
 * <p>Manages identity creation and listing, and any number of realms: each
 * {@code session.attach} either creates a realm and its first connector or adds
 * a connector to a realm that already exists.
 */
public class DaemonController implements DaemonServer.RequestHandler {

    private static final Logger log = LoggerFactory.getLogger(DaemonController.class);

    private final SeedStore seedStore;
    private final FileIdentityStore identityStore;
    private final Path configDir;

    private KeyMasterController currentCtrl;

    public DaemonController(SeedStore seedStore, FileIdentityStore identityStore, Path configDir) {
        this.seedStore = seedStore;
        this.identityStore = identityStore;
        this.configDir = configDir;
    }

    @Override
    public JsonObject handle(String method, JsonObject params) {
        log.debug("RPC: {} {}", method, params);
        return switch (method) {
            case "identity.create" -> identityCreate(params);
            case "identity.list" -> identityList();
            case "identity.show" -> identityShow(params);
            case "session.attach" -> sessionAttach(params);
            case "session.detach" -> sessionDetach(params);
            case "session.status" -> sessionStatus();
            default -> error("unknown method: " + method);
        };
    }

    private JsonObject identityCreate(JsonObject params) {
        String identity = requireString(params, "identity");
        if (identity == null) {
            return error("missing 'identity' parameter");
        }
        String pgpName = requireString(params, "pgp_name");
        if (pgpName == null) pgpName = identity;
        String pgpEmail = requireString(params, "pgp_email");
        if (pgpEmail == null) pgpEmail = identity;

        if (!seedStore.exists()) {
            return error("No seed found. Run 'kv-cli seed generate' first.");
        }

        // The daemon's own controller, so the key metadata store that realms
        // resolve against is the same instance this write goes through.
        // FileKeyMetaDataStore loads its keys at construction, so a second
        // instance would leave the controller's view stale.
        KeyMasterController ctrl = controller(null);
        String pubkey;
        if (params.has("creation_time")) {
            long creationTime = params.get("creation_time").getAsLong();
            pubkey = ctrl.createIdentity(identity, pgpName, pgpEmail, creationTime);
        } else {
            pubkey = ctrl.createIdentity(identity, pgpName, pgpEmail);
        }
        identityStore.add(identity, pubkey);

        JsonObject result = new JsonObject();
        result.addProperty("identity", identity);
        result.addProperty("pubkey", pubkey);
        return result;
    }

    private JsonObject identityList() {
        var entries = identityStore.list();
        JsonArray arr = new JsonArray();
        for (var entry : entries) {
            JsonObject obj = new JsonObject();
            obj.addProperty("identity", entry.identity());
            obj.addProperty("pubkey", entry.pubkey());
            arr.add(obj);
        }
        JsonObject result = new JsonObject();
        result.add("identities", arr);
        return result;
    }

    private JsonObject identityShow(JsonObject params) {
        String identity = requireString(params, "identity");
        if (identity == null) {
            return error("missing 'identity' parameter");
        }

        var entry = identityStore.get(identity);
        if (entry == null) {
            return error("Identity not found: " + identity);
        }

        JsonObject result = new JsonObject();
        result.addProperty("identity", entry.identity());
        result.addProperty("pubkey", entry.pubkey());
        return result;
    }

    private JsonObject sessionAttach(JsonObject params) {
        String descriptorPath = requireString(params, "descriptor");
        if (descriptorPath == null) {
            return error("missing 'descriptor' parameter");
        }
        String policy = requireString(params, "policy");

        try {
            String descriptorJson = Files.readString(Path.of(descriptorPath));
            AvatarDescriptor descriptor = AvatarDescriptor.fromJson(descriptorJson);

            KeyMasterController ctrl = controller(policy);

            // "connect to an existing realm" — the join outcome of a QR scan
            if (params.has("realm_id") && !params.get("realm_id").isJsonNull()) {
                int realmId = params.get("realm_id").getAsInt();
                Realm realm = ctrl.getRealm(realmId);
                if (realm == null) {
                    return error("No such realm: " + realmId);
                }
                Realm.AttachResult result = ctrl.attachToRealm(realmId, descriptor);
                return attachResult(realm, result);
            }

            // "create a new realm"
            String identity = requireString(params, "identity");
            if (identity == null) {
                return error("missing 'identity' parameter");
            }
            Identity primary = new Identity(identity);
            List<IdentitySelection> selections = parseSelections(params, primary);
            if (selections == null) {
                return error("'identities' entries need an identity and optional protocols");
            }

            Realm realm = ctrl.createRealm(requireString(params, "realm_name"),
                    primary, selections);
            try {
                Realm.AttachResult result = realm.attach(descriptor);
                return attachResult(realm, result);
            } catch (Exception e) {
                ctrl.detachRealm(realm.id());
                throw e;
            }
        } catch (Exception e) {
            log.error("Attach failed", e);
            return error("Attach failed: " + e.getMessage());
        }
    }

    /**
     * The realm's selections: the primary identity, plus whatever the optional
     * {@code identities} array carries. Entries are either a plain identity
     * string or an object with an identity and a list of protocol names, which
     * is how a per-identity protocol filter reaches the daemon — expressible
     * only because selection is data rather than a predicate.
     *
     * @return the selections, or {@code null} if an entry is malformed
     */
    private List<IdentitySelection> parseSelections(JsonObject params, Identity primary) {
        List<IdentitySelection> selections = new ArrayList<>();
        selections.add(new IdentitySelection(primary));

        if (!params.has("identities") || !params.get("identities").isJsonArray()) {
            return selections;
        }
        for (JsonElement element : params.getAsJsonArray("identities")) {
            String name;
            Set<Integer> coinTypes = Set.of();
            if (element.isJsonPrimitive()) {
                name = element.getAsString();
            } else if (element.isJsonObject()) {
                JsonObject entry = element.getAsJsonObject();
                name = requireString(entry, "identity");
                if (entry.has("protocols") && entry.get("protocols").isJsonArray()) {
                    Set<Integer> parsed = new LinkedHashSet<>();
                    for (JsonElement protocol : entry.getAsJsonArray("protocols")) {
                        Integer coinType = coinTypeOf(protocol.getAsString());
                        if (coinType == null) {
                            return null;
                        }
                        parsed.add(coinType);
                    }
                    coinTypes = parsed;
                }
            } else {
                return null;
            }
            if (name == null || name.isBlank()) {
                return null;
            }
            if (!name.equals(primary.name())) {
                selections.add(new IdentitySelection(new Identity(name), coinTypes));
            }
        }
        return selections;
    }

    private static Integer coinTypeOf(String protocol) {
        return switch (protocol.toLowerCase()) {
            case "ssh" -> Protocol.SSH.coinType();
            case "gpg", "openpgp" -> Protocol.OPENPGP.coinType();
            case "nostr" -> Protocol.NOSTR.coinType();
            case "mls" -> Protocol.MLS.coinType();
            default -> null;
        };
    }

    private JsonObject attachResult(Realm realm, Realm.AttachResult result) {
        JsonObject json = new JsonObject();
        json.addProperty("sessionId", result.attachEventId());
        json.addProperty("realmId", realm.id());
        json.addProperty("realmName", realm.name());
        json.addProperty("connectorId", result.connectorId());
        json.addProperty("identity", realm.primaryIdentity().name());
        json.add("identities", names(realm));
        return json;
    }

    /**
     * The daemon's single controller, created on first use. Realms come and go
     * within it; the controller itself holds the vault and the metadata store.
     *
     * @param policy {@code "auto"} for auto-approval, otherwise the policy file
     *               plus an interactive prompt. Applies to every realm, since
     *               approval policy is controller-wide here
     */
    private KeyMasterController controller(String policy) {
        if (currentCtrl == null) {
            KeyVault vault = new Bip32KeyVault(seedStore.getMnemonic(), seedStore.getPassphrase());
            var keyStore = new FileKeyMetaDataStore(configDir);
            currentCtrl = new KeyMasterController(new KeyMaster(vault, keyStore));
        }
        if (policy != null) {
            ApprovalHandler handler = "auto".equals(policy)
                    ? new AutoApprovalHandler()
                    : new PolicyConfig(configDir.resolve("policy.conf"),
                            new KDialogApprovalHandler());
            currentCtrl.setApprovalHandler(handler);
        }
        return currentCtrl;
    }

    private JsonObject sessionDetach(JsonObject params) {
        if (currentCtrl == null || currentCtrl.realms().isEmpty()) {
            JsonObject result = new JsonObject();
            result.addProperty("status", "ok");
            result.addProperty("message", "Not attached.");
            return result;
        }

        try {
            boolean hasRealm = params != null && params.has("realm_id")
                    && !params.get("realm_id").isJsonNull();
            boolean hasConnector = params != null && params.has("connector_id")
                    && !params.get("connector_id").isJsonNull();

            if (hasRealm && hasConnector) {
                currentCtrl.detach(params.get("realm_id").getAsInt(),
                        params.get("connector_id").getAsInt());
            } else if (hasRealm) {
                currentCtrl.detachRealm(params.get("realm_id").getAsInt());
            } else {
                currentCtrl.detachAll();
            }
        } catch (Exception e) {
            log.error("Detach error", e);
            return error("Detach failed: " + e.getMessage());
        }

        JsonObject result = new JsonObject();
        result.addProperty("status", "ok");
        return result;
    }

    private JsonObject sessionStatus() {
        JsonObject result = new JsonObject();
        boolean attached = currentCtrl != null && !currentCtrl.realms().isEmpty();
        result.addProperty("attached", attached);

        JsonArray realms = new JsonArray();
        if (currentCtrl != null) {
            for (Realm realm : currentCtrl.realms().values()) {
                JsonObject json = new JsonObject();
                json.addProperty("realmId", realm.id());
                json.addProperty("realmName", realm.name());
                json.addProperty("identity", realm.primaryIdentity().name());
                json.add("identities", names(realm));
                JsonArray connectors = new JsonArray();
                realm.connectorIds().forEach(connectors::add);
                json.add("connectors", connectors);
                realms.add(json);
            }
        }
        result.add("realms", realms);
        return result;
    }

    private static JsonArray names(Realm realm) {
        JsonArray arr = new JsonArray();
        realm.identityNames().forEach(arr::add);
        return arr;
    }

    /**
     * Detach the current session if any. Called during daemon shutdown.
     */
    void shutdown() {
        if (currentCtrl != null) {
            try {
                currentCtrl.detachAll();
            } catch (Exception e) {
                log.warn("Shutdown detach error", e);
            }
            currentCtrl = null;
        }
    }

    private static JsonObject error(String message) {
        JsonObject obj = new JsonObject();
        obj.addProperty("error", message);
        return obj;
    }

    private static String requireString(JsonObject params, String key) {
        if (params.has(key) && !params.get(key).isJsonNull()) {
            return params.get(key).getAsString();
        }
        return null;
    }
}
