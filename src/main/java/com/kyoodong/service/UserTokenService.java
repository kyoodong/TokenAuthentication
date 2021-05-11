package com.kyoodong.service;

import com.kyoodong.Base64;
import com.kyoodong.CryptoKey;
import com.kyoodong.TokenType;
import com.kyoodong.Utils;
import com.kyoodong.exceptions.InvalidTokenException;
import com.kyoodong.repository.UserTokenRepository;
import com.kyoodong.token.Token;
import com.kyoodong.token.UserToken;

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
        String secretKey = Base64.encodeToString(CryptoKey.generateAesKey());
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
            secretKey,
            accessToken.getExpiredAt(),
            refreshToken.getExpiredAt()
        );
        repository.save(userId, encryptedAccessToken);
        return userToken;
    }

    public int validateToken(Token accessToken) {
        accessToken.validate();

        int userId = accessToken.getInt(1);
        String tokenString = accessToken.make(cryptoKey.getSecretKey());
        String savedAccessToken = repository.get(userId);

        if (!tokenString.equals(savedAccessToken)) {
            throw new InvalidTokenException();
        }
        return userId;
    }

//    public UserToken refresh(String accessKey, String refreshKey) {
//        TODO
//    }
}
