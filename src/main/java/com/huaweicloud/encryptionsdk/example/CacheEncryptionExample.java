package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * @description: 基于密钥缓存的加解密示例，缓存同时支持kms和本地主密钥
 */
public class CacheEncryptionExample {

    private static final String PLAIN_TEXT = "Hello World!";

    public static void main(String[] args) {

        HuaweiCrypto huaweiCrypto = EncryptCodeExtract.getHuaweiCrypto();

        // 创建缓存对象
        LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
        // 设置数据密钥最大缓存容量，超出容量则按照LUR规则进行删除
        localDataKeyCache.setCapacity(10);

        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        // 初始化数据密钥缓存管理器
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(localDataKeyCache,
            huaweiConfig);
        // 单个被缓存的数据密钥加密byte最大数量限制，默认为Long.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        // 单个被缓存的数据密钥加密数据条数最大限制,默认为Integer.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(1000);
        // 数据密钥缓存存活时间，单位为ms，默认为1000s
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("key", "value");
        // 加密
        CryptoResult<byte[]> encryptResult = huaweiCrypto.encrypt(
            new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        byte[] cipherResult = encryptResult.getResult();
        // 解密
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(cipherResult);
        System.out.println(new String(decrypt.getResult()));
        Validate.isTrue(PLAIN_TEXT.equals(new String(decrypt.getResult()).intern()));

    }
}
