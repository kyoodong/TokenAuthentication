package com.kyoodong;

import com.kyoodong.token.Token;
import org.springframework.http.HttpHeaders;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;

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
        String tokenType = request.getAttribute("TOKEN_TYPE").toString();
        if (tokenType == null || tokenType.equals("TOKEN_TEMP")) {
            contentCachingResponseWrapper.copyBodyToResponse();
            return;
        }

        HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(httpResponse);
        String token = getToken(httpRequest);
        if (tokenType.equals("TOKEN_ANONYMOUS")) {
            Token anonymousToken = Token.from(token, cryptoKey.getSecretKey());
            String clientKey = anonymousToken.getString(0);
            byte[] responseData = AES256.get().encrypt(body, clientKey.getBytes());
            responseWrapper.getOutputStream().write(responseData);
            return;
        }

        if (tokenType.equals("TOKEN_USER")) {
            Token userToken = Token.from(token, cryptoKey.getSecretKey());
            byte[] secretKey = userToken.getByteArray(0);
            byte[] responseData = AES256.get().encrypt(body, secretKey);
            responseWrapper.getOutputStream().write(responseData);
            return;
        }
    }

    @Override
    public void destroy() {

    }

    private String getToken(HttpServletRequest request) {
        return getBearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    private String getBearerToken(String bearer) {
        return bearer.split(" ")[1];
    }
}
