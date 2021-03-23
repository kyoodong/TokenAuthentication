package com.kyoodong;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA2048 implements Crypto {

    private static RSA2048 rsa2048 = new RSA2048();

    public static RSA2048 get() {
        return rsa2048;
    }

    private RSA2048() {

    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "SunJCE"); // 알고리즘 명 / Cipher 알고리즘 mode / padding
            X509EncodedKeySpec ukeySpec = new X509EncodedKeySpec(key);
            KeyFactory ukeyFactory = KeyFactory.getInstance("RSA");
            PublicKey publickey = ukeyFactory.generatePublic(ukeySpec);

            cipher.init(Cipher.ENCRYPT_MODE, publickey);

            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }

        throw new RuntimeException();
    }

    @Override
    public byte[] encrypt(String data, byte[] key) {
        return encrypt(data.getBytes(), key);
    }

    @Override
    public String encryptToString(byte[] data, byte[] key) {
        return Base64.encodeToString(encrypt(data, key));
    }

    @Override
    public String encryptToString(String data, byte[] key) {
        return Base64.encodeToString(encrypt(data, key));
    }

    @Override
    public byte[] decrypt(byte[] data, byte[] key) {
        try {
            byte[] decodedData = Base64.decode(data);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "SunJCE");
            PKCS8EncodedKeySpec rkeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory rkeyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = rkeyFactory.generatePrivate(rkeySpec);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(decodedData);
        } catch (Exception e) {
            e.printStackTrace();
        }

        throw new RuntimeException();
    }

    @Override
    public byte[] decrypt(String data, byte[] key) {
        return decrypt(Base64.decode(data), key);
    }

    @Override
    public String decryptToString(byte[] data, byte[] key) {
        return new String(decrypt(data, key));
    }

    @Override
    public String decryptToString(String data, byte[] key) {
        return new String(decrypt(Base64.decode(data), key));
    }
}
