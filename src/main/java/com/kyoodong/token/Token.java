package com.kyoodong.token;

import com.kyoodong.AES256;
import com.kyoodong.Base64;
import com.kyoodong.TokenType;
import com.kyoodong.exceptions.ExpiredTokenException;
import com.kyoodong.exceptions.InvalidTokenException;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Token {

    private static final String DELIMITER = ":";

    private List<byte[]> extraList = new ArrayList<>();
    private String appId;
    private String refreshKey;
    private TokenType tokenType;
    private LocalDateTime createdAt;

    public Token(String appId, String refreshKey, TokenType tokenType) {
        this.appId = appId;
        this.refreshKey = refreshKey;
        this.tokenType = tokenType;
        this.createdAt = LocalDateTime.now();
    }

    public Token(String appId, String refreshKey, TokenType tokenType, LocalDateTime createdAt) {
        this.appId = appId;
        this.refreshKey = refreshKey;
        this.tokenType = tokenType;
        this.createdAt = createdAt;
    }

    public String make(byte[] key) {
        List<String> dataList = new ArrayList<>(
            Arrays.asList(
                String.valueOf(tokenType.ordinal()),
                String.valueOf(createdAt.toEpochSecond(ZoneOffset.UTC)),
                appId,
                refreshKey,
                String.valueOf(extraList.size())
            )
        );

        int extraSize = 0;
        for (byte[] data : this.extraList) {
            dataList.add(String.valueOf(data.length));
            extraSize += data.length;
        }

        byte[] dataString = String.join(DELIMITER, dataList).getBytes();
        if (dataString.length >= Byte.MAX_VALUE) {
            throw new InvalidTokenException();
        }

        ByteBuffer byteBuffer = ByteBuffer
            .allocate(4 + dataString.length + extraSize)
            .putInt(dataString.length)
            .put(dataString);

        for (byte[] data : this.extraList) {
            byteBuffer.put(data);
        }

        return AES256.get().encryptToString(byteBuffer.array(), key);
    }

    public static Token from(String token, byte[] secretKey) {
        byte[] decrypted = AES256.get().decrypt(Base64.decode(token), secretKey);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decrypted);

        int dataStringLength = byteBuffer.getInt();
        byte[] dataString = new byte[dataStringLength];
        byteBuffer.get(dataString, 0, dataStringLength);

        String[] datas = new String(dataString).split(DELIMITER);
        TokenType tokenType = TokenType.values()[Integer.parseInt(datas[0])];
        LocalDateTime createdAt = LocalDateTime.ofInstant(
            Instant.ofEpochSecond(Long.parseLong(datas[1])),
            ZoneOffset.UTC
        );
        String appId = datas[2];
        String refreshKey = datas[3];
        int extraSize = Integer.parseInt(datas[4]);

        Token newToken = new Token(appId, refreshKey, tokenType, createdAt);
        for (int i = 0; i < extraSize; i++) {
            int index = i + 5;
            int size = Integer.parseInt(datas[index]);
            byte[] data = new byte[size];
            byteBuffer.get(data, 0, size);
            newToken.addData(data);
        }

        return newToken;
    }

    public void refresh(String refreshKey) {
        if (LocalDateTime.now().isAfter(getExpiredAt())) {
            throw new ExpiredTokenException();
        }

        if (!this.refreshKey.equals(refreshKey)) {
            throw new InvalidTokenException();
        }

        this.createdAt = LocalDateTime.now();
        this.refreshKey = refreshKey;
    }

    public boolean isValid() {
        if (tokenType == TokenType.TEMP_TOKEN || tokenType == TokenType.ANONYMOUS_TOKEN) {
            return extraList.size() == 1;
        }

        return false;
    }

    public Token addData(String data) {
        this.extraList.add(data.getBytes());
        return this;
    }

    public Token addData(int data) {
        this.extraList.add(ByteBuffer.allocate(4).putInt(data).array());
        return this;
    }

    public Token addData(byte[] data) {
        this.extraList.add(data);
        return this;
    }

    public int getInt(int index) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.put(this.extraList.get(index));
        return buffer.getInt(0);
    }

    public String getString(int index) {
        return new String(this.extraList.get(index));
    }

    public byte[] getByteArray(int index) {
        return this.extraList.get(index);
    }

    public LocalDateTime getExpiredAt() {
        return createdAt.plusSeconds(tokenType.lifeTime.getSeconds());
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public List<byte[]> getExtraList() {
        return extraList;
    }
}
