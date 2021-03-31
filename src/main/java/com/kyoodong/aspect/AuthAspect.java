package com.kyoodong.aspect;

import com.kyoodong.Constant;
import com.kyoodong.service.AnonymousTokenService;
import com.kyoodong.service.TempTokenService;
import com.kyoodong.service.UserTokenService;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.http.HttpHeaders;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

public class AuthAspect {

    private final UserTokenService userTokenService;
    private final TempTokenService tempTokenService;
    private final AnonymousTokenService anonymousTokenService;

    public AuthAspect(UserTokenService userTokenService, TempTokenService tempTokenService, AnonymousTokenService anonymousTokenService) {
        this.userTokenService = userTokenService;
        this.tempTokenService = tempTokenService;
        this.anonymousTokenService = anonymousTokenService;
    }

    @Pointcut("@annotation(com.kyoodong.annotation.TempAuth)")
    public void tempAuth() { }

    @Pointcut("@annotation(com.kyoodong.annotation.AnonymousAuth)")
    public void anonymousAuth() { }

    @Pointcut("@annotation(com.kyoodong.annotation.UserAuth)")
    public void userAuth() { }

    @Before("tempAuth()")
    public void beforeTempAuth(JoinPoint joinPoint) {
        String token = getToken();
        tempTokenService.validateToken(token);
        setToken(token);
        setType(Constant.TOKEN_TEMP);
    }

    @Before("anonymousAuth()")
    public void beforeAnonymousAuth(JoinPoint joinPoint) {
        String token = getToken();
        anonymousTokenService.validateToken(token);
        setToken(token);
        setType(Constant.TOKEN_ANONYMOUS);
    }

    @Before("userAuth()")
    public void beforeUserAuth(JoinPoint joinPoint) {
        String token = getToken();
        int userId = userTokenService.validateToken(token);
        setToken(token);
        setUserId(userId);
        setType(Constant.TOKEN_USER);
    }

    private void setUserId(int userId) {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.getRequestAttributes())).getRequest();
        request.setAttribute(Constant.USER_ID, userId);
    }

    private void setToken(String token) {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.getRequestAttributes())).getRequest();
        request.setAttribute(Constant.TOKEN, token);
    }

    private void setType(String type) {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.getRequestAttributes())).getRequest();
        request.setAttribute(Constant.TOKEN_TYPE, type);
    }

    private String getToken() {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.getRequestAttributes())).getRequest();
        return getBearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    private String getBearerToken(String bearer) {
        return bearer.split(" ")[1];
    }
}
