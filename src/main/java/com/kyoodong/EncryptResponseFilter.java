package com.kyoodong;

import com.kyoodong.token.Token;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;

@Order(10)
public class EncryptResponseFilter implements Filter {

    private final CryptoKey cryptoKey;

    public EncryptResponseFilter(CryptoKey cryptoKey) {
        this.cryptoKey = cryptoKey;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        ContentCachingResponseWrapper contentCachingResponseWrapper = new ContentCachingResponseWrapper(httpResponse);

        chain.doFilter(httpRequest, contentCachingResponseWrapper);

        String body = new String(contentCachingResponseWrapper.getContentAsByteArray());
        Object tokenTypeObj = request.getAttribute(Constant.TOKEN_TYPE);
        HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(httpResponse);

        if (tokenTypeObj == null) {
            contentCachingResponseWrapper.copyBodyToResponse();
            return;
        }

        String token = getToken(httpRequest);
        if (token != null) {
            Token userToken = Token.from(token, cryptoKey.getSecretKey());
            byte[] secretKey = userToken.getByteArray(0);
            byte[] responseData = AES256.get().encryptToString(body, secretKey).getBytes();
            responseWrapper.setContentLength(responseData.length);
            responseWrapper.getOutputStream().write(responseData);
        } else {
            contentCachingResponseWrapper.copyBodyToResponse();
        }
    }

    @Override
    public void destroy() {

    }

    // TODO: 하나로 합치기
    private String getToken(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            return authorization;
        }
        return getBearerToken(authorization);
    }

    private String getBearerToken(String bearer) {
        return bearer.split(" ")[1];
    }
}
