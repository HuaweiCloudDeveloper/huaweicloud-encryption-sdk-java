package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.codec.DecoderException;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @description: 使用KMSDiscoveryKeyring密钥环进行解密无需再传递keyId，regionId，projectId等信息，仅需ak，sk即可
 */
public class KmsDiscoveryEncryptionExample {
    private static final String ACCESS_KEY = "ak";
    // Secret Access Key
    private static final String SECRET_ACCESS_KEY = "sk";
    // 项目id
    private static final String PROJECT_ID = "projectId";
    // 地区节点，与项目id一一UI对应
    private static final String REGION = "cn-north-7";
    // kms服务上主密钥id
    private static final String KEYID = "keyId";

    // 需要加密的数据
    private static final String PLAIN_TEXT = "Hello World!";

    // KMS服务接口版本信息，当前固定为v1.0
    private static final String KMS_INTERFACE_VERSION = "v1.0";

    public static void main(String[] args) throws IOException, DecoderException, NoSuchAlgorithmException {
        // 初始化kms相关信息及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY)
                .buildKmsConfig(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID)))
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                // 开启discover密钥环
                .buildDiscovery(true)
                .build();
        // 选择kms密钥环类型
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        // 初始化加密加解密入口类
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        // 加密上下文
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        // 加密数据
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));

        // discover解密
        HuaweiConfig huaweiConfigDiscovery = HuaweiConfig.builder().buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY).build();
        KMSKeyring keyringDiscovery = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_DISCOVERY.getType());
        HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDiscovery).withKeyring(keyringDiscovery);
        CryptoResult<byte[]> decrypt = huaweiCryptoDecrypt.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        Assert.assertEquals(decrypt.getResult(), PLAIN_TEXT.getBytes(StandardCharsets.UTF_8));
    }
}
