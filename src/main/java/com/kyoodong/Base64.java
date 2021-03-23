package com.kyoodong;

import java.nio.charset.StandardCharsets;

public class Base64 {

    public static byte[] encode(String content) {
        return java.util.Base64.getEncoder().encode(toByteArray(content));
    }

    public static String encodeToString(String content) {
        return java.util.Base64.getEncoder().encodeToString(toByteArray(content));
    }

    public static String encodeToString(byte[] data) {
        return java.util.Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decode(String base64) {
        return java.util.Base64.getDecoder().decode(base64);
    }

    public static byte[] decode(byte[] data) {
        return java.util.Base64.getDecoder().decode(data);
    }

    public static String decodeToString(String base64) {
        return new String(java.util.Base64.getDecoder().decode(base64));
    }

    public static String decodeToString(byte[] data) {
        return new String(java.util.Base64.getDecoder().decode(data));
    }

    private static byte[] toByteArray(String content) {
        return content.getBytes();
    }
}
