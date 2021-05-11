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

    private CryptoKey cryptoKey = new CryptoKey(
        "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",
        "NDMwZjk5MTAtZjE2NC00Ng=="
    );
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
    public void test_decryptTempToken() {
        String clientKey = "1234567890123456";
        String data = "BRKE3I7vhWwaL0GYrNfamr+1wVJWyIrR0FazxDEy9N2nhpwUXS3hi+cT9n79o9LRpjN6zhDoSUuCBag5uPJqEvm+G6Ol5DK11vT0R8+87Jf5Yjc7Gof4Oh6bLXb6wClU";
        System.out.println(AES256.get().decryptToString(data, clientKey.getBytes()));
    }

    @Test
    public void test_decryptUserToken() {
        byte[] secretKey = Base64.decode("XfgQ0S/m5Rh/cX7CEwnQBw==");
        String data = "XEqByu4VCAw5rTx7THfAvE6/NvfiPDOiZNaFo+/q44dNj1dlLQQ9B55fNOpzt7P4CyU10SM8KH+fd/H2XSVSa/WSou5BtcftRe8MafUDPfrK0JO/5qMnpydO2anrThzW";
        System.out.println(AES256.get().decryptToString(data, secretKey));
    }

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
        UserTokenService.ValidateResult result = userTokenService.validateToken(userToken.getAccessToken());
        Assertions.assertEquals(1, result.getUserId());
    }
}
