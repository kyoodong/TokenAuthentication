package com.kyoodong;

import java.util.UUID;

public class Utils {

    public static String getRandomString() {
        return UUID.randomUUID().toString().substring(0, 10);
    }
}
