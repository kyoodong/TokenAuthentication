package com.kyoodong.service;

import com.kyoodong.Base64;
import com.kyoodong.CryptoKey;
import com.kyoodong.TokenType;
import com.kyoodong.Utils;
import com.kyoodong.exceptions.ExpiredTokenException;
import com.kyoodong.exceptions.InvalidTokenException;
import com.kyoodong.exceptions.InvalidTokenTypeException;
import com.kyoodong.repository.UserTokenRepository;
import com.kyoodong.token.Token;
import com.kyoodong.token.UserToken;

import java.time.LocalDateTime;

public class UserTokenService {

    private String appId;
    private CryptoKey cryptoKey;
    private UserTokenRepository repository;

    public UserTokenService(String appId, CryptoKey cryptoKey, UserTokenRepository repository) {
        this.appId = appId;
        this.cryptoKey = cryptoKey;
        this.repository = repository;
    }

    public UserToken createToken(int userId) {
        byte[] secretKey = CryptoKey.generateAesKey();
        Token accessToken = new Token(appId, Utils.getRandomString(), TokenType.ACCESS_TOKEN)
            .addData(secretKey)
            .addData(userId);
        String encryptedAccessToken = accessToken.make(cryptoKey.getSecretKey());

        Token refreshToken = new Token(appId, Utils.getRandomString(), TokenType.REFRESH_TOKEN)
            .addData(encryptedAccessToken.substring(0, 16));
        String encryptedRefreshToken = refreshToken.make(cryptoKey.getSecretKey());

        UserToken userToken = new UserToken(
            encryptedAccessToken,
            encryptedRefreshToken,
            Base64.encodeToString(secretKey),
            accessToken.getExpiredAt(),
            refreshToken.getExpiredAt()
        );
        repository.save(userId, userToken);
        return userToken;
    }

    public int validateToken(String accessToken) {
        Token token = Token.from(accessToken, cryptoKey.getSecretKey());
        if (token.getTokenType() != TokenType.ACCESS_TOKEN) {
            throw new InvalidTokenTypeException();
        }

        if (LocalDateTime.now().isAfter(token.getExpiredAt())) {
            throw new ExpiredTokenException();
        }

        int userId = token.getInt(1);
        UserToken userToken = repository.get(userId);

        if (userToken == null || !userToken.getAccessToken().equals(accessToken)) {
            throw new InvalidTokenException();
        }

        return userId;
    }

//    public UserToken refreshToken() {
//        return UserToken
//    }
}
