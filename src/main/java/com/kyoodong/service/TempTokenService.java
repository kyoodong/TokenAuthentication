package com.kyoodong.service;

import com.kyoodong.*;
import com.kyoodong.token.Token;

public class TempTokenService {

    private String appId;
    private CryptoKey cryptoKey;

    public TempTokenService(String appId, CryptoKey cryptoKey) {
        this.appId = appId;
        this.cryptoKey = cryptoKey;
    }

    public String createToken(String encryptedClientKey) {
        String clientKey = RSA2048.get().decryptToString(encryptedClientKey, cryptoKey.getPrivateKey());
        String refreshKey = Utils.getRandomString();

        Token token = new Token(appId, refreshKey, TokenType.TEMP_TOKEN);
        token.addData(clientKey);
        String encryptedToken = token.make(cryptoKey.getSecretKey());
        return AES256.get().encryptToString(encryptedToken, clientKey.getBytes());
    }
}
