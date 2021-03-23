package com.kyoodong.service;

import com.kyoodong.AES256;
import com.kyoodong.CryptoKey;
import com.kyoodong.Utils;
import com.kyoodong.TokenType;
import com.kyoodong.enumeration.OS;
import com.kyoodong.token.Token;

import java.time.LocalDateTime;

public class AnonymousTokenService {

    private String appId;
    private CryptoKey cryptoKey;

    public AnonymousTokenService(String appId, CryptoKey cryptoKey) {
        this.appId = appId;
        this.cryptoKey = cryptoKey;
    }

    public String createToken(
        String tempToken,
        OS os,
        String encryptedSignature
    ) {
        Token token = Token.from(tempToken, cryptoKey.getSecretKey());
        if (!token.isValid()) {
            throw new RuntimeException();
        }

        String clientKey = token.getString(0);
        String signature = AES256.get().decryptToString(encryptedSignature, clientKey.getBytes());
        String secretKey = token.getString(0);
        String randomString = Utils.getRandomString();
        Token newToken = new Token(appId, randomString, TokenType.ANONYMOUS_TOKEN, LocalDateTime.now());
        newToken.addData(secretKey);
        newToken.addData(os.ordinal());
        newToken.addData(signature);
        return AES256.get().encryptToString(newToken.make(cryptoKey.getSecretKey()), clientKey.getBytes());
    }
}
