package com.kyoodong.service;

import com.kyoodong.*;
import com.kyoodong.enumeration.OS;
import com.kyoodong.exceptions.ExpiredTokenException;
import com.kyoodong.exceptions.InvalidTokenException;
import com.kyoodong.token.Token;

import java.time.LocalDateTime;

public class AnonymousTokenService {

    private String appId;
    private CryptoKey cryptoKey;
    private TempTokenService tempTokenService;
    private SignatureValidator signatureValidator;

    public AnonymousTokenService(String appId, CryptoKey cryptoKey, TempTokenService tempTokenService, SignatureValidator signatureValidator) {
        this.appId = appId;
        this.cryptoKey = cryptoKey;
        this.tempTokenService = tempTokenService;
        this.signatureValidator = signatureValidator;
    }

    public String createToken(
        String tempToken,
        OS os,
        String encryptedSignature
    ) {
        Token token = Token.from(tempToken, cryptoKey.getSecretKey());
        tempTokenService.validateToken(token);

        String clientKey = token.getString(0);
        String signature = AES256.get().decryptToString(encryptedSignature, clientKey.getBytes());
        String randomString = Utils.getRandomString();
        Token newToken = new Token(appId, randomString, TokenType.ANONYMOUS_TOKEN, LocalDateTime.now());
        newToken.addData(clientKey);
        newToken.addData(os.ordinal());
        newToken.addData(signature);
        return AES256.get().encryptToString(newToken.make(cryptoKey.getSecretKey()), clientKey.getBytes());
    }

    public void validateToken(String anonymousToken) {
        Token token = Token.from(anonymousToken, cryptoKey.getSecretKey());
        if (token.getExtraList().size() != 3) {
            throw new InvalidTokenException();
        }

        if (LocalDateTime.now().isAfter(token.getExpiredAt())) {
            throw new ExpiredTokenException();
        }

        String signature = token.getString(2);
        if (!signatureValidator.validate(signature)) {
            throw new InvalidTokenException();
        }
    }
}
