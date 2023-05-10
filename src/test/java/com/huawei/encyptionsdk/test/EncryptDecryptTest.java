package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author zc
 * @ClassName EncryptDecryptTest
 * @description:
 * @datetime 2022年 09月 16日 14:58
 */
public class EncryptDecryptTest {
    public static final String ACCESS_KEY = "WN0ETTDULCBZDCPDMBR8";
    public static final String SECRET_ACCESS_KEY = "M7dOePlpneNQmKSVSAIV6Vp2zNtwfoGM3Lf4QIod";
    public static final String PROJECT_ID = "7c55d8e5238d42e49fd9ce11b24b035b";
    public static final String REGION = "cn-north-7";
    public static final String KEYID = "aac33b45-d65e-49ea-82c3-e6f5c552dbc5";
    public static final String END_POINT = "https://kms.cn-north-7.myhuaweicloud.com";

    public static final String PROJECT_ID1 = "7c55d8e5238d42e49fd9ce11b24b035b";
    public static final String REGION1 = "cn-north-74";
    public static final String KEYID1 = "dd967cf1-f611-4371-ba74-69efec2d92a0";

    private static final String PLAIN_TEXT = "Hello World!";

    public static HuaweiConfig huaweiConfig = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
            .buildAk(ACCESS_KEY)
            .buildKmsConfig(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID,END_POINT)))
            .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .buildDiscovery(true)
            .build();

    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSEncrypt()  {

        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt1 = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));


        //discover 解密
        HuaweiConfig huaweiConfigDecrypt = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY).build();
        KMSKeyring keyringDecrypt = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_DISCOVERY.getType());
        HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDecrypt).withKeyring(keyringDecrypt);
        CryptoResult<byte[]> decrypt = huaweiCryptoDecrypt.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        Assert.assertEquals(new String(decrypt.getResult()).intern(), PLAIN_TEXT);
    }


    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSMultiKeyRingEncrypt()  {
        List<KMSConfig> list = new ArrayList<>();
        list.add(new KMSConfig(REGION, KEYID, PROJECT_ID,END_POINT));
        list.add(new KMSConfig(REGION1, KEYID1, PROJECT_ID1,END_POINT));
        HuaweiConfig multiConfig = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY)
                .buildKmsConfig(list)
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(multiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt1 = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));


        //discover 解密
        HuaweiConfig multiDecryptConfig = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY)
                .buildKmsConfig(Collections.singletonList(new KMSConfig(REGION1, KEYID1, PROJECT_ID1)))
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        HuaweiCrypto decryptHuaweiCrypto = new HuaweiCrypto(multiDecryptConfig).withKeyring(keyring);
        CryptoResult<byte[]> decrypt = decryptHuaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));

    }


    @Test
    public void Should_ok_When_RawAESEncrypt()  {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/256bit")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        //解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM4GCMEncrypt()  {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM4_GCN.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/128bit")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        //解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM4CBCEncrypt()  {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM4_CBC.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/128bit")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        //解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM2Encrypt()  {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM2.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/pri.txt")));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/pub.txt")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        //解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawRSAEncrypt()  {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_128_GCM_NOPADDING)
                .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapri.txt")));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/rsapub.txt")));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        //解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

}
