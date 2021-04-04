package com.kyoodong.service;

import com.kyoodong.*;
import com.kyoodong.exceptions.ExpiredTokenException;
import com.kyoodong.exceptions.InvalidTokenException;
import com.kyoodong.token.Token;

import java.time.LocalDateTime;

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

    public void validateToken(String tempToken) {
        Token token = Token.from(tempToken, cryptoKey.getSecretKey());
        validateToken(token);
    }

    public void validateToken(Token tempToken) {
        if (LocalDateTime.now().isAfter(tempToken.getExpiredAt())) {
            throw new ExpiredTokenException();
        }

        if (tempToken.getExtraList().size() != 1) {
            throw new InvalidTokenException();
        }
    }
}
