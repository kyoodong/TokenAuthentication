package com.kyoodong;


import com.kyoodong.enumeration.OS;
import com.kyoodong.repository.UserTokenRepository;
import com.kyoodong.service.AnonymousTokenService;
import com.kyoodong.service.TempTokenService;
import com.kyoodong.service.UserTokenService;
import com.kyoodong.token.UserToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

public class TokenTest {

    private CryptoKey cryptoKey = new CryptoKey();
    private TempTokenService tempTokenService = new TempTokenService("appId", cryptoKey);
    private AnonymousTokenService anonymousService = new AnonymousTokenService("appId", cryptoKey, tempTokenService, new SignatureValidator() {
        @Override
        public boolean validate(String signature) {
            return true;
        }
    });
    private UserTokenService userTokenService = new UserTokenService("appId", cryptoKey, new UserTokenRepository() {
        Map<Integer, UserToken> map = new HashMap<>();

        @Override
        public void save(int userId, UserToken token) {
            map.put(userId, token);
        }

        @Override
        public UserToken get(int userId) {
            return map.get(userId);
        }
    });

    @Test
    public void test_tempToken_암복호화() {
        // client
        String clientKey = "1234567890123456";

        // encryptedClientKey 를 서버에 전송
        String encryptedClientKey = Base64.encodeToString(RSA2048.get().encryptToString(clientKey, cryptoKey.getPublicKey()));

        // 서버로부터 전달 받은(암호화된) tempToken
        String encryptedTempToken = tempTokenService.createToken(encryptedClientKey);

        // 복호화된 tempToken = 서버로 이대로 요청을 날리면 됨
        String tempToken = AES256.get().decryptToString(encryptedTempToken, clientKey.getBytes());
        tempTokenService.validateToken(tempToken);

        //
        String signature = "0123456789123456";
        String encryptedSignature = AES256.get().encryptToString(signature.getBytes(), clientKey.getBytes());

        // 서버로부터 전달 받은 anonymousToken
        String encryptedAnonymousToken = anonymousService.createToken(tempToken, OS.ANDROID, encryptedSignature);
        String anonymousToken = AES256.get().decryptToString(encryptedAnonymousToken, clientKey.getBytes());
        anonymousService.validateToken(anonymousToken);

        UserToken userToken = userTokenService.createToken(1);
        int userId = userTokenService.validateToken(userToken.getAccessToken());
        Assertions.assertEquals(1, userId);
    }
}
