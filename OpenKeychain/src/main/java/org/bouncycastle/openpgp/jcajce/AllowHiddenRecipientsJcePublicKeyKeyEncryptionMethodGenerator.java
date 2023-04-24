package org.bouncycastle.openpgp.jcajce;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class AllowHiddenRecipientsJcePublicKeyKeyEncryptionMethodGenerator extends JcePublicKeyKeyEncryptionMethodGenerator {
    private PGPPublicKey key;
    private boolean hiddenRecipients;

    public AllowHiddenRecipientsJcePublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key, boolean hiddenRecipients) {
        super(key);
        this.key = key;
        this.hiddenRecipients = hiddenRecipients;
    }

    public ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
            throws PGPException {
        long keyId = hiddenRecipients ? 0L : key.getKeyID();
        return new PublicKeyEncSessionPacket(keyId, key.getAlgorithm(), processSessionInfo(encryptSessionInfo(key, sessionInfo)));
    }
}
