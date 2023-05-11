package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import org.apache.commons.codec.DecoderException;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * FileEncryptTest
 */
public class FileEncryptTest {

    @Test
    public void Should_ok_When_RawRSATXTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapri.txt")));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapub.txt")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        FileInputStream fileInputStream = new FileInputStream("src/test/resources/128bit");
        FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/128bit.encrypted");
        huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        FileInputStream in = new FileInputStream("src/test/resources/128bit.encrypted");
        FileOutputStream out = new FileOutputStream("src/test/resources/128bit.decrypted");
        huaweiCrypto.decrypt(in, out);
        // 解密
    }

    @Test
    public void Should_ok_When_RawRSAPPTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapri.txt")));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapub.txt")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        FileInputStream fileInputStream = new FileInputStream("src/test/resources/test.pptx");
        FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/test.encrypted.pptx");
        huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        FileInputStream in = new FileInputStream("src/test/resources/test.encrypted.pptx");
        FileOutputStream out = new FileOutputStream("src/test/resources/test.decrypted.pptx");
        huaweiCrypto.decrypt(in, out);
        // 解密
    }


    @Test
    public void Should_ok_When_RawAESPPTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/256bit")));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        FileInputStream fileInputStream = new FileInputStream("src/test/resources/test.pptx");
        FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/test.encrypted.pptx");
        huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        FileInputStream in = new FileInputStream("src/test/resources/test.encrypted.pptx");
        FileOutputStream out = new FileOutputStream("src/test/resources/test.decrypted.pptx");
        // 解密
        huaweiCrypto.decrypt(in, out);
    }

    @Test
    public void Should_ok_When_CacheDataKeyFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/256bit")));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(), huaweiConfig);
        cacheCryptoMeterialManager.setMaxByteLimit(5000000);
        cacheCryptoMeterialManager.setSurvivalTime(10000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        FileInputStream fileInputStream = new FileInputStream("src/test/resources/test.pptx");
        FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/test.encrypted.pptx");
        huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        fileInputStream.close();
        fileOutputStream.close();
        FileInputStream in = new FileInputStream("src/test/resources/test.encrypted.pptx");
        FileOutputStream out = new FileOutputStream("src/test/resources/test.decrypted.pptx");
        // 第一次解密
        huaweiCrypto.decrypt(in, out);
        in.close();
        out.close();
        // 通过缓存加解密
        FileInputStream fileInputStreamCache = new FileInputStream("src/test/resources/test.pptx");
        FileOutputStream fileOutputStreamCache = new FileOutputStream("src/test/resources/test.encrypted.Cache.pptx");
        huaweiCrypto.encrypt(fileInputStreamCache, fileOutputStreamCache, map);
        fileInputStreamCache.close();
        fileOutputStreamCache.close();
        FileInputStream inCache = new FileInputStream("src/test/resources/test.encrypted.Cache.pptx");
        FileOutputStream outCache = new FileOutputStream("src/test/resources/test.decrypted.Cache.pptx");
        huaweiCrypto.decrypt(inCache, outCache);
        inCache.close();
        outCache.close();
    }

    /**
     * jar包中无大文件，打包时单元测试无法通过，固注销
     */
    // @Test
    public void Should_ok_When_FileSizeGreaterThanOneGB() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/128bit")));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        FileInputStream fileInputStream = new FileInputStream("D:\\test.rar");
        FileOutputStream fileOutputStream = new FileOutputStream("D:\\test.encrypted.rar");
        Long startTime = System.currentTimeMillis();
        huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        long encryptTime = System.currentTimeMillis() - startTime;
        System.out.println(encryptTime);
        FileInputStream in = new FileInputStream("D:\\test.encrypted.rar");
        FileOutputStream out = new FileOutputStream("D:\\test.decrypted.rar");
        huaweiCrypto.decrypt(in, out);
        // 解密
        long decryptTime = System.currentTimeMillis() - startTime;
        System.out.println(decryptTime);
    }
}
