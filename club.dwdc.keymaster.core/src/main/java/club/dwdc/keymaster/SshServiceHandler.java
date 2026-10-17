package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Service handler for SSH agent operations.
 *
 * <p>Provides {@code request_identities} and {@code sign_request} methods
 * backed by a {@link KeyVault} and a list of {@link KeyEntry} objects.
 */
public class SshServiceHandler extends AbstractServiceHandler {

    public SshServiceHandler(KeyVault vault, List<KeyEntry> keys) {
        super(vault, keys);
    }

    /**
     * Return the list of SSH identities (public key blobs + comments).
     */
    @ServiceMethod(value = "request_identities", defaultPolicy = ApprovalPolicy.APPROVE)
    public List<SshIdentity> requestIdentities() {
        checkApproval("request_identities", "SSH identity listing");
        List<SshIdentity> identities = new ArrayList<>();
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            byte[] blob = buildSshEd25519KeyBlob(pubResult.data());
            String comment = key.metadata() != null
                    ? key.metadata().getOrDefault("comment", "")
                    : "";
            identities.add(new SshIdentity(blob, comment));
        }
        return identities;
    }

    /**
     * Sign data with the key matching the request's key blob.
     *
     * @throws IllegalArgumentException if no key matches the request blob
     */
    @ServiceMethod(value = "sign_request", defaultPolicy = ApprovalPolicy.ASK)
    public SshSignResponse signRequest(SshSignRequest request) {
        checkApproval("sign_request", "SSH signing request");
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            byte[] blob = buildSshEd25519KeyBlob(pubResult.data());
            if (Arrays.equals(blob, request.keyBlob())) {
                VaultResult signResult = vault.execute(KeyVault.FN_SIGN, request.data(), key.toVaultPath());
                if (!signResult.isOk()) {
                    throw new IllegalStateException("sign failed: status=" + signResult.status());
                }
                return new SshSignResponse(signResult.data(), "ssh-ed25519");
            }
        }
        throw new IllegalArgumentException("key-mismatch");
    }

    /**
     * Build an SSH Ed25519 key blob in SSH wire format:
     * {@code string("ssh-ed25519") + string(pubkey)}
     */
    public static byte[] buildSshEd25519KeyBlob(byte[] pubKey) {
        byte[] algo = "ssh-ed25519".getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + algo.length + 4 + pubKey.length);
        buf.putInt(algo.length);
        buf.put(algo);
        buf.putInt(pubKey.length);
        buf.put(pubKey);
        return buf.array();
    }

    /**
     * Returns the SSH authorized_keys line for the given identity's Ed25519 key.
     * Format: {@code ssh-ed25519 <base64-key-blob> <identity>}
     *
     * @param vault    vault for key derivation
     * @param identity identity identifier (e.g. "alice@atlanta.com")
     * @return authorized_keys line
     */
    public static String getAuthorizedKeysLine(KeyVault vault, String identity) {
        int[] sshPath = IdentityPaths.ssh(new Identity(identity));

        VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, sshPath);
        if (!pubResult.isOk()) {
            throw new IllegalStateException("Failed to derive SSH key: status=" + pubResult.status());
        }

        byte[] keyBlob = buildSshEd25519KeyBlob(pubResult.data());
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(keyBlob) + " " + identity;
    }
}
