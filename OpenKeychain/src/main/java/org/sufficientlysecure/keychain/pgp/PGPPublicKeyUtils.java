/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.pgp;


import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.sufficientlysecure.keychain.util.IterableIterator;
import org.sufficientlysecure.keychain.util.Utf8Util;


@SuppressWarnings("unchecked") // BouncyCastle doesn't do generics here :(
public class PGPPublicKeyUtils {

    static PGPPublicKey keepOnlyRawUserId(PGPPublicKey masterPublicKey, byte[] rawUserIdToKeep) {
        boolean elementToKeepFound = false;

        Iterator<byte[]> it = masterPublicKey.getRawUserIDs();
        while (it.hasNext()) {
            byte[] rawUserId = it.next();
            if (Arrays.equals(rawUserId, rawUserIdToKeep)) {
                elementToKeepFound = true;
            } else {
                masterPublicKey = PGPPublicKey.removeCertification(masterPublicKey, rawUserId);
            }
        }

        if (!elementToKeepFound) {
            throw new NoSuchElementException();
        }
        return masterPublicKey;
    }

    static PGPPublicKey keepOnlyUserId(PGPPublicKey masterPublicKey, String userIdToKeep) {
        boolean elementToKeepFound = false;

        Iterator<byte[]> it = masterPublicKey.getRawUserIDs();
        while (it.hasNext()) {
            byte[] rawUserId = it.next();
            String userId = Utf8Util.fromUTF8ByteArrayReplaceBadEncoding(rawUserId);
            if (userId.contains(userIdToKeep)) {
                elementToKeepFound = true;
            } else {
                masterPublicKey = PGPPublicKey.removeCertification(masterPublicKey, rawUserId);
            }
        }

        if (!elementToKeepFound) {
            throw new NoSuchElementException();
        }
        return masterPublicKey;
    }

    static PGPPublicKey keepOnlySelfCertsForUserIds(PGPPublicKey masterPubKey) {
        long masterKeyId = masterPubKey.getKeyID();

        Iterator<byte[]> it = masterPubKey.getRawUserIDs();
        while (it.hasNext()) {
            byte[] rawUserId = it.next();
            masterPubKey = keepOnlySelfCertsForRawUserId(masterPubKey, masterKeyId, rawUserId);
        }

        return masterPubKey;
    }

    private static PGPPublicKey keepOnlySelfCertsForRawUserId(
            PGPPublicKey masterPubKey, long masterKeyId, byte[] rawUserId) {
        Iterator<PGPSignature> it = masterPubKey.getSignaturesForID(rawUserId);
        while (it.hasNext()) {
            PGPSignature sig = it.next();
            if (sig.getKeyID() != masterKeyId) {
                masterPubKey = PGPPublicKey.removeCertification(masterPubKey, rawUserId, sig);
            }
        }
        return masterPubKey;
    }

    static PGPPublicKey removeAllUserAttributes(PGPPublicKey masterPubKey) {
        Iterator<PGPUserAttributeSubpacketVector> it = masterPubKey.getUserAttributes();

        while (it.hasNext()) {
            masterPubKey = PGPPublicKey.removeCertification(masterPubKey, it.next());
        }

        return masterPubKey;
    }

    static PGPPublicKey removeAllDirectKeyCerts(PGPPublicKey masterPubKey) {
        Iterator<PGPSignature> it = masterPubKey.getSignaturesOfType(PGPSignature.DIRECT_KEY);

        while (it.hasNext()) {
            masterPubKey = PGPPublicKey.removeCertification(masterPubKey, it.next());
        }

        return masterPubKey;
    }

    /**
     * Create a new stripped secret key from a given public key, using the GNU DUMMY s2k type
     * with an empty secret body.
     *
     * @param publicKey a public key object
     * @return a stripped secret key object
     */
    static PGPSecretKey constructGnuDummyKey(PGPPublicKey publicKey) {
        SecretKeyPacket secret;
        if (publicKey.isMasterKey()) {
            secret = new SecretKeyPacket(
                    publicKey.getPublicKeyPacket(),
                    // this is a dummy anyways, use CAST5 for compatibility (it's what gpg does)
                    SymmetricKeyAlgorithmTags.CAST5,
                    new S2K(S2K.GNUDummyParams.noPrivateKey()), null, null);
        } else {
            secret = new SecretSubkeyPacket(
                    publicKey.getPublicKeyPacket(),
                    // this is a dummy anyways, use CAST5 for compatibility (it's what gpg does)
                    SymmetricKeyAlgorithmTags.CAST5,
                    new S2K(S2K.GNUDummyParams.noPrivateKey()), null, null);
        }
        return new PGPSecretKey(secret, publicKey);
    }

    /**
     * Create a new stripped secret key from a given public key, using the GNU DUMMY
     * divert-to-card s2k type, giving a serial number as iv.
     *
     * @param publicKey a public key object
     * @param serial the serial number of the card, written as iv in the packet
     * @return a stripped secret key object
     */
    static PGPSecretKey constructGnuDummyKey(PGPPublicKey publicKey, byte[] serial) {
        SecretKeyPacket secret;

        byte[] iv = new byte[16];
        System.arraycopy(serial, 0, iv, 0, serial.length > 16 ? 16 : serial.length);

        if (publicKey.isMasterKey()) {
            secret = new SecretKeyPacket(
                    publicKey.getPublicKeyPacket(),
                    SymmetricKeyAlgorithmTags.NULL,
                    SecretKeyPacket.USAGE_CHECKSUM,
                    new S2K(S2K.GNUDummyParams.divertToCard()), iv, null);
        } else {
            secret = new SecretSubkeyPacket(
                    publicKey.getPublicKeyPacket(),
                    SymmetricKeyAlgorithmTags.NULL,
                    SecretKeyPacket.USAGE_CHECKSUM,
                    new S2K(S2K.GNUDummyParams.divertToCard()), iv, null);
        }
        return new PGPSecretKey(secret, publicKey);
    }

    static PGPSecretKeyRing constructGnuDummyKeyRing(PGPPublicKeyRing pubRing) {
        return constructGnuDummyKeyRing(pubRing, null);
    }

    static PGPSecretKeyRing constructGnuDummyKeyRing(PGPPublicKeyRing pubRing, byte[] cardSerial) {

        List<PGPSecretKey> keys = new ArrayList<>();


        for (PGPPublicKey pubKey : new IterableIterator<>(pubRing.getPublicKeys()))
        {
            PGPSecretKey secKey;

            if (cardSerial != null) {
                secKey = constructGnuDummyKey(pubKey, cardSerial);
            } else {
                secKey = constructGnuDummyKey(pubKey);
            }

            keys.add(secKey);
        }

        return new PGPSecretKeyRing(keys);
    }

    /**
     * Add a subkey binding certification, changing the key type from master to subkey.
     *
     * @param key the key the revocation is to be added to.
     * @param certification the key signature to be added.
     * @return the new changed public key object.
     */
    static PGPPublicKey addSubkeyBindingCertification(
            PGPPublicKey    key,
            PGPSignature    certification)
    {
        // make sure no subSigs are previously present
        if (!key.isMasterKey())
        {
            throw new IllegalArgumentException("key is already a subkey!");
        }

        try {
            Method buildPublicKey = PGPSecretKey.class.getDeclaredMethod("buildPublicKey", boolean.class, PGPPublicKey.class);
            buildPublicKey.setAccessible(true);
            key = (PGPPublicKey) buildPublicKey.invoke(null, false, key);

            Field subSigs = PGPPublicKey.class.getDeclaredField("subSigs");
            subSigs.setAccessible(true);
            subSigs.set(key, new ArrayList<>(Collections.singleton(certification)));
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
        return key;
    }

    public static byte[] getEncSessionKey(PGPPublicKeyEncryptedData encData) {
        try {
            Field keyData = PGPPublicKeyEncryptedData.class.getDeclaredField("keyData");
            keyData.setAccessible(true);
            return ((PublicKeyEncSessionPacket) keyData.get(encData)).getEncSessionKey()[0];
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
