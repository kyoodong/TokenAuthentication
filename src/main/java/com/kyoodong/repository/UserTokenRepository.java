package com.kyoodong.repository;

public interface UserTokenRepository {

    void save(int userId, String accessToken);

    String get(int userId);
}
