package com.kyoodong.service;

import com.kyoodong.exceptions.InvalidHashException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ResponseValidateService {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public void validateHash(
        String hash,
        byte[] secretKey,
        byte[] body,
        String token,
        long timestamp
    ) {
        byte[] tokenBytes = token.getBytes();
        byte[] timestampBytes = getBytes(timestamp);
        ByteBuffer byteBuffer = ByteBuffer.allocate(tokenBytes.length + body.length + timestampBytes.length);
        byteBuffer.put(tokenBytes);
        byteBuffer.put(body);
        byteBuffer.put(timestampBytes);

        String generatedHash = hmacSha512(byteBuffer.array(), secretKey);
        if (!hash.equals(generatedHash)) {
            throw new InvalidHashException();
        }
    }

    private String hmacSha512(byte[] message, byte[] key) {
        Mac sha512Hmac;
        final String HMAC_SHA512 = "HmacSHA512";

        try {
            sha512Hmac = Mac.getInstance(HMAC_SHA512);
            SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_SHA512);
            sha512Hmac.init(keySpec);
            byte[] macData = sha512Hmac.doFinal(message);

            // Can either base64 encode or put it right into hex
            return bytesToHex(macData);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private byte[] getBytes(long value) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.putLong(value);
        return byteBuffer.array();
    }
}
