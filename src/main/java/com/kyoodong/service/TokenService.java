package com.kyoodong.service;

public interface TokenService<T> {

    T createToken();

    boolean validateToken(T t);

    T refreshToken(T t);
}
