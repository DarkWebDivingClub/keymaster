package club.dwdc.keymaster;

/**
 * Transport connector — abstracts protocol-specific transport between
 * KeyMaster and an Avatar.
 *
 * <p>Implementations handle relay connection, attach/detach handshake,
 * and service request routing. KeyMaster delegates all transport concerns
 * to a Connector instance.
 */
public interface Connector {

    /**
     * Connect to the Avatar described by the given descriptor.
     *
     * @param descriptor avatar endpoint description (relay, xpub, services)
     * @param signer     identity signer for the attach handshake
     * @return attach event ID
     * @throws Exception if connection or attach fails
     */
    String connect(AvatarDescriptor descriptor, NostrIdentitySigner signer) throws Exception;

    /**
     * Disconnect from the currently connected Avatar.
     *
     * @throws Exception if detach or close fails
     */
    void disconnect() throws Exception;
}
