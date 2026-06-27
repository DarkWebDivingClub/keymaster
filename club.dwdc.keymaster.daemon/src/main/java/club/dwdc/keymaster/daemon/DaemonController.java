package club.dwdc.keymaster.daemon;

import club.dwdc.keymaster.ApprovalHandler;
import club.dwdc.keymaster.AvatarDescriptor;
import club.dwdc.keymaster.KeyMaster;
import club.dwdc.keymaster.KeyMasterController;
import club.dwdc.keymaster.desktop.AutoApprovalHandler;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keymaster.desktop.KDialogApprovalHandler;
import club.dwdc.keymaster.desktop.PolicyConfig;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.SeedStore;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Business logic for the KeyMaster daemon — implements JSON-RPC method dispatch.
 *
 * <p>Manages identity creation/listing and a single attach session at a time.
 */
public class DaemonController implements DaemonServer.RequestHandler {

    private static final Logger log = LoggerFactory.getLogger(DaemonController.class);

    private final SeedStore seedStore;
    private final FileIdentityStore identityStore;
    private final Path configDir;

    private KeyMasterController currentCtrl;
    private String currentSessionId;
    private String currentIdentity;

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
            case "session.detach" -> sessionDetach();
            case "session.status" -> sessionStatus();
            default -> error("unknown method: " + method);
        };
    }

    private JsonObject identityCreate(JsonObject params) {
        String identity = requireString(params, "identity");
        if (identity == null) {
            return error("missing 'identity' parameter");
        }

        if (!seedStore.exists()) {
            return error("No seed found. Run 'kv-cli seed generate' first.");
        }

        KeyVault vault = new Bip32KeyVault(seedStore.getMnemonic(), seedStore.getPassphrase());
        KeyMaster km = new KeyMaster(vault);
        KeyMasterController ctrl = new KeyMasterController(km);
        ctrl.createIdentity(identity);

        String pubkey = km.getPubKeyHex();
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
        if (currentCtrl != null) {
            return error("Already attached. Detach first.");
        }

        String descriptorPath = requireString(params, "descriptor");
        String identity = requireString(params, "identity");
        String policy = params.has("policy") ? params.get("policy").getAsString() : null;

        if (descriptorPath == null) {
            return error("missing 'descriptor' parameter");
        }
        if (identity == null) {
            return error("missing 'identity' parameter");
        }

        if (!seedStore.exists()) {
            return error("No seed found. Run 'kv-cli seed generate' first.");
        }

        try {
            String descriptorJson = Files.readString(Path.of(descriptorPath));
            AvatarDescriptor descriptor = AvatarDescriptor.fromJson(descriptorJson);

            KeyVault vault = new Bip32KeyVault(seedStore.getMnemonic(), seedStore.getPassphrase());
            KeyMaster km = new KeyMaster(vault);
            KeyMasterController ctrl = new KeyMasterController(km);
            ctrl.createIdentity(identity);

            ApprovalHandler handler;
            if ("auto".equals(policy)) {
                handler = new AutoApprovalHandler();
            } else {
                Path policyPath = configDir.resolve("policy.conf");
                handler = new PolicyConfig(policyPath, new KDialogApprovalHandler());
            }
            ctrl.setApprovalHandler(handler);

            String sessionId = ctrl.attach(descriptor);

            if (!identityStore.exists(identity)) {
                identityStore.add(identity, km.getPubKeyHex());
            }

            this.currentCtrl = ctrl;
            this.currentSessionId = sessionId;
            this.currentIdentity = identity;

            JsonObject result = new JsonObject();
            result.addProperty("sessionId", sessionId);
            result.addProperty("identity", identity);
            return result;
        } catch (Exception e) {
            log.error("Attach failed", e);
            return error("Attach failed: " + e.getMessage());
        }
    }

    private JsonObject sessionDetach() {
        if (currentCtrl == null) {
            JsonObject result = new JsonObject();
            result.addProperty("status", "ok");
            result.addProperty("message", "Not attached.");
            return result;
        }

        try {
            currentCtrl.detach();
        } catch (Exception e) {
            log.error("Detach error", e);
        } finally {
            currentCtrl = null;
            currentSessionId = null;
            currentIdentity = null;
        }

        JsonObject result = new JsonObject();
        result.addProperty("status", "ok");
        return result;
    }

    private JsonObject sessionStatus() {
        JsonObject result = new JsonObject();
        result.addProperty("attached", currentCtrl != null);
        if (currentCtrl != null) {
            result.addProperty("identity", currentIdentity);
            result.addProperty("sessionId", currentSessionId);
        }
        return result;
    }

    /**
     * Detach the current session if any. Called during daemon shutdown.
     */
    void shutdown() {
        if (currentCtrl != null) {
            try {
                currentCtrl.detach();
            } catch (Exception e) {
                log.warn("Shutdown detach error", e);
            }
            currentCtrl = null;
            currentSessionId = null;
            currentIdentity = null;
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
