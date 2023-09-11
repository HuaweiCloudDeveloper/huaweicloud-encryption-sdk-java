package com.huaweicloud.encryptionsdk.util;

import java.util.HashMap;
import java.util.Map;

public class CommonUtils {

    public static Map<String, String> getEncryptoMap() {
        // 加密上下文
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        return map;
    }
    public static Map<String, String> getEncryptionContext() {
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("encryption", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("caching", "encrypt");
        return encryptionContext;
    }
}
