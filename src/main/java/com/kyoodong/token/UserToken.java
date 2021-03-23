package com.kyoodong.token;

import java.time.LocalDateTime;

public class UserToken {

    private String accessToken;
    private String refreshToken;
    private String secretKey;
    private LocalDateTime accessTokenExpiredAt;
    private LocalDateTime refreshTokenExpiredAt;

    public UserToken(String accessToken, String refreshToken, String secretKey, LocalDateTime accessTokenExpiredAt, LocalDateTime refreshTokenExpiredAt) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.secretKey = secretKey;
        this.accessTokenExpiredAt = accessTokenExpiredAt;
        this.refreshTokenExpiredAt = refreshTokenExpiredAt;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public LocalDateTime getAccessTokenExpiredAt() {
        return accessTokenExpiredAt;
    }

    public LocalDateTime getRefreshTokenExpiredAt() {
        return refreshTokenExpiredAt;
    }
}
