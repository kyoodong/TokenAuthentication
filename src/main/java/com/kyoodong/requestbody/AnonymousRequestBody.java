package com.kyoodong.requestbody;

import com.kyoodong.enumeration.OS;

public class AnonymousRequestBody {

    private OS os;
    private String encryptedSignature;

    public OS getOs() {
        return os;
    }

    public String getEncryptedSignature() {
        return encryptedSignature;
    }
}
