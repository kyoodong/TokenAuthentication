package com.kyoodong;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

public class CryptoKey {

    private byte[] publicKey;
    private byte[] privateKey;
    private byte[] secretKey;
    private static KeyGenerator aesKeyGenerator = null;

    static {
        try {
            aesKeyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public CryptoKey() {
        try {
            String randomKey = UUID.randomUUID().toString().substring(0, 16);
            secretKey = randomKey.getBytes();
            SecureRandom random = new SecureRandom(randomKey.getBytes());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","SunJSSE");

            // key 생성
            generator.initialize(2048, random);
            KeyPair keyPair = generator.generateKeyPair();
            publicKey = keyPair.getPublic().getEncoded();
            privateKey = keyPair.getPrivate().getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] generateAesKey() {
        return aesKeyGenerator.generateKey().getEncoded();
    }

    public CryptoKey(String publicKey, String privateKey, String secretKey) {
        this.publicKey = Base64.decode(publicKey);
        this.privateKey = Base64.decode(privateKey);
        this.secretKey = Base64.decode(secretKey);
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }
}
