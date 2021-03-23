package com.kyoodong;

public interface Crypto {

    byte[] encrypt(byte[] data, byte[] key);
    byte[] encrypt(String data, byte[] key);
    String encryptToString(byte[] data, byte[] key);
    String encryptToString(String data, byte[] key);


    byte[] decrypt(byte[] data, byte[] key);
    byte[] decrypt(String data, byte[] key);
    String decryptToString(byte[] data, byte[] key);
    String decryptToString(String data, byte[] key);
}
