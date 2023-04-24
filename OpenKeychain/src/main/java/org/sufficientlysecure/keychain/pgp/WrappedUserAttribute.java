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

import com.google.auto.value.AutoValue;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketInputStream;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;

public class WrappedUserAttribute implements Serializable {

    public static final int UAT_NONE = 0;
    public static final int UAT_IMAGE = UserAttributeSubpacketTags.IMAGE_ATTRIBUTE;
    public static final int UAT_URI_ATTRIBUTE = 101;

    private UserAttributeSubpacket[] mSubpackets;

    WrappedUserAttribute(PGPUserAttributeSubpacketVector vector) {
        try {
            Field field = PGPUserAttributeSubpacketVector.class.getDeclaredField("packets");
            field.setAccessible(true);
            mSubpackets = (UserAttributeSubpacket[]) field.get(vector);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private WrappedUserAttribute(UserAttributeSubpacket subpacket) {
        mSubpackets = new UserAttributeSubpacket[] { subpacket };
    }

    PGPUserAttributeSubpacketVector getVector() {
        return PGPUserAttributeSubpacketVector.fromSubpackets(mSubpackets);
    }

    public int getType() {
        if (mSubpackets.length > 0) {
            return mSubpackets[0].getType();
        }
        return 0;
    }

    public static WrappedUserAttribute fromSubpacket (int type, byte[] data) {
        Constructor<UserAttributeSubpacket> constructor;
        try {
            constructor = UserAttributeSubpacket.class.getDeclaredConstructor(int.class, byte[].class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        constructor.setAccessible(true);

        try {
            return new WrappedUserAttribute(constructor.newInstance(type, data));
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] getEncoded () throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (UserAttributeSubpacket subpacket : mSubpackets) {
            subpacket.encode(out);
        }
        return out.toByteArray();
    }

    public static WrappedUserAttribute fromData (byte[] data) throws IOException {
        UserAttributeSubpacketInputStream in =
                new UserAttributeSubpacketInputStream(new ByteArrayInputStream(data));
        ArrayList<UserAttributeSubpacket> list = new ArrayList<>();
        while (in.available() > 0) {
            list.add(in.readPacket());
        }
        UserAttributeSubpacket[] result = new UserAttributeSubpacket[list.size()];
        list.toArray(result);
        return new WrappedUserAttribute(
                PGPUserAttributeSubpacketVector.fromSubpackets(result));
    }

    /** Writes this object to an ObjectOutputStream. */
    private void writeObject(java.io.ObjectOutputStream out) throws IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BCPGOutputStream bcpg = new BCPGOutputStream(baos);
        bcpg.writePacket(new UserAttributePacket(mSubpackets));
        out.writeObject(baos.toByteArray());

    }

    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {

        byte[] data = (byte[]) in.readObject();
        BCPGInputStream bcpg = new BCPGInputStream(new ByteArrayInputStream(data));
        Packet p = bcpg.readPacket();
        if ( ! UserAttributePacket.class.isInstance(p)) {
            throw new IOException("Could not decode UserAttributePacket!");
        }
        mSubpackets = ((UserAttributePacket) p).getSubpackets();
    }

    public byte[][] getSubpackets() {
        UserAttributeSubpacket[] subpackets = mSubpackets;
        byte[][] ret = new byte[subpackets.length][];
        for (int i = 0; i < subpackets.length; i++) {
            ret[i] = subpackets[i].getData();
        }
        return ret;
    }

    private void readObjectNoData() throws ObjectStreamException {
    }

    @SuppressWarnings("SimplifiableIfStatement")
    @Override
    public boolean equals(Object o) {
        if (!WrappedUserAttribute.class.isInstance(o)) {
            return false;
        }
        return Arrays.equals(mSubpackets, ((WrappedUserAttribute) o).mSubpackets);
    }

}
