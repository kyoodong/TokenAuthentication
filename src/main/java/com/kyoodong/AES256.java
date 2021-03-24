package com.kyoodong;

import com.kyoodong.exceptions.DecryptException;
import com.kyoodong.exceptions.EncryptException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class AES256 implements Crypto {

    private static final AES256 aes256 = new AES256();

    public static AES256 get() {
        return aes256;
    }

    private AES256() {}

    @Override
    public byte[] encrypt(byte[] data, byte[] secretKey) {
        try {
            byte[] iv;
            if (secretKey.length > 16) {
                iv = Arrays.copyOfRange(secretKey, 0, 16);
            } else {
                iv = secretKey;
            }
            SecretKey secureKey = new SecretKeySpec(secretKey, "AES");

            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(iv));

            return c.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new EncryptException();
    }

    @Override
    public byte[] encrypt(String data, byte[] secretKey) {
        return encrypt(data.getBytes(), secretKey);
    }

    @Override
    public String encryptToString(byte[] data, byte[] secretKey) {
        return Base64.encodeToString(encrypt(data, secretKey));
    }

    @Override
    public String encryptToString(String data, byte[] secretKey) {
        return Base64.encodeToString(encrypt(data.getBytes(), secretKey));
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] secretKey) {
        try {
            byte[] iv;
            if (secretKey.length > 16) {
                iv = Arrays.copyOfRange(secretKey, 0, 16);
            } else {
                iv = secretKey;
            }

            SecretKey secureKey = new SecretKeySpec(secretKey, "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(iv));

            return c.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new DecryptException();
    }

    @Override
    public byte[] decrypt(String data, byte[] secretKey) {
        return decrypt(Base64.decode(data), secretKey);
    }

    @Override
    public String decryptToString(String data, byte[] secretKey) {
        return new String(decrypt(Base64.decode(data), secretKey));
    }

    @Override
    public String decryptToString(byte[] data, byte[] secretKey) {
        return new String(decrypt(data, secretKey));
    }
}
