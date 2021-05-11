package com.kyoodong.aspect;

import com.kyoodong.Constant;
import com.kyoodong.TokenType;
import com.kyoodong.exceptions.NotRequiredTokenException;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class AuthAspect {

    @Pointcut("@annotation(com.kyoodong.annotation.TempAuth)")
    public void tempAuth() { }

    @Pointcut("@annotation(com.kyoodong.annotation.AnonymousAuth)")
    public void anonymousAuth() { }

    @Pointcut("@annotation(com.kyoodong.annotation.UserAuth)")
    public void userAuth() {}

    @Before("tempAuth()")
    public void beforeTempAuth(JoinPoint joinPoint) {
        TokenType tokenType = getTokenType();
        if (tokenType != TokenType.TEMP_TOKEN) {
            throw new NotRequiredTokenException();
        }
    }

    @Before("anonymousAuth()")
    public void beforeAnonymousAuth(JoinPoint joinPoint) throws IOException {
        TokenType tokenType = getTokenType();
        if (tokenType != TokenType.ANONYMOUS_TOKEN) {
            throw new NotRequiredTokenException();
        }
    }

    @Before("userAuth()")
    public void beforeUserAuth(JoinPoint joinPoint) throws IOException {
        TokenType tokenType = getTokenType();
        if (tokenType != TokenType.ACCESS_TOKEN) {
            throw new NotRequiredTokenException();
        }
    }

    private TokenType getTokenType() {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.getRequestAttributes())).getRequest();
        return TokenType.valueOf(request.getAttribute(Constant.TOKEN_TYPE).toString());
    }
}
