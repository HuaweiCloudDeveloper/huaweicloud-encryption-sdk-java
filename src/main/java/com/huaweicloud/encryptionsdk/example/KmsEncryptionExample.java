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
import com.huaweicloud.encryptionsdk.util.CommonUtils;
import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @description: kms简单数据加密示例
 */
public class KmsEncryptionExample {

    // Access Key Id
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

    public static void main(String[] args) {
        // 封装region，keyId，projectId信息，可支持多个region
        List<KMSConfig> kmsConfigList = Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID));
        // 初始化kms相关信息及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .sk(SECRET_ACCESS_KEY)
            .ak(ACCESS_KEY)
            .kmsConfigList(kmsConfigList)
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        // 选择kms密钥环类型
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        // 初始化加密加解密入口类
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        // 加密数据
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        // 解密数据
        CryptoResult<byte[]> decrypt1 = huaweiCrypto.decrypt(result.getResult());
        Validate.isTrue(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8).equals(decrypt1.getResult()));
    }
}
