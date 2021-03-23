package com.kyoodong.repository;

import com.kyoodong.token.UserToken;

public interface UserTokenRepository {

    void save(int userId, UserToken token);

    UserToken get(int userId);
}
