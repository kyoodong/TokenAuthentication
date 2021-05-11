package com.kyoodong;

import java.time.Duration;

public enum TokenType {
    TEMP_TOKEN(Duration.ofMinutes(5)),
    ANONYMOUS_TOKEN(Duration.ofHours(1)),
    ACCESS_TOKEN(Duration.ofHours(1)),
    REFRESH_TOKEN(Duration.ofDays(30)),
    NONE(null);

    public final Duration lifeTime;

    TokenType(Duration lifeTime) {
        this.lifeTime = lifeTime;
    }
}
