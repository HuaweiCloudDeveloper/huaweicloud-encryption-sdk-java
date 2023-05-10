package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.codec.DecoderException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertSame;

/**
 * @description: 基于密钥缓存的加解密示例，缓存同时支持kms和本地主密钥
 */
public class CacheEncryptionExample {

    private static final String PLAIN_TEXT = "Hello World!";


    public static void main(String[] args) throws IOException, DecoderException, NoSuchAlgorithmException {
        //初始化加解密相关配置及加密算法
        HuaweiConfig config = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();

        //选择本地密钥环类型，包括sm4,aes,rsa,sm2等四种
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        //读取密钥保存在文件中的一到多个密钥，也可通过String类型密钥字符串getByte()获取，参照LocalAesKeyringEncryptionExample
        //设置RSA密钥环加密使用的公钥，加密数据前设置
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/rsapub.txt")));
        //设置RSA密钥环加密使用的私钥，解密数据前设置
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/rsapri.txt")));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(config).withKeyring(keyring);

        //创建缓存对象
        LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
        //设置数据密钥最大缓存容量，超出容量则按照LUR规则进行删除
        localDataKeyCache.setCapacity(10);

        //初始化数据密钥缓存管理器
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(localDataKeyCache, config);
        //单个被缓存的数据密钥加密byte最大数量限制，默认为Long.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        //单个被缓存的数据密钥加密数据条数最大限制,默认为Integer.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(10);
        //数据密钥缓存存活时间，单位为ms，默认为1000s
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        //加密上下文
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("key", "value");
        //加密
        CryptoResult<byte[]> encryptResult = huaweiCrypto.encrypt(new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        byte[] cipherResult = encryptResult.getResult();
        //解密
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(cipherResult);
        System.out.println(new String(decrypt.getResult()));
        assertSame(new String(decrypt.getResult()).intern(), PLAIN_TEXT);

    }
}
