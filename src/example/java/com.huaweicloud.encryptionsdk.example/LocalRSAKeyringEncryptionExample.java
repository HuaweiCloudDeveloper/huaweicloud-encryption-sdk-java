package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
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

/**
 * @description: 本地非对称主密钥RSA密钥环简单加解密
 */
public class LocalRSAKeyringEncryptionExample {

    private static final String PLAIN_TEXT = "Hello World!";


    public static void main(String[] args) throws IOException, DecoderException, NoSuchAlgorithmException {
        //初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
                .build();
        //选择本地密钥环类型，包括sm4,aes,rsa,sm2等四种，非对称加密包括RSA和SM2
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());

        //读取密钥保存在文件中的一到多个密钥，也可通过String类型密钥字符串getByte()获取，参照LocalAesKeyringEncryptionExample
        //设置RSA密钥环加密使用的公钥，加密数据前设置
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList("src/rsapub.txt")));
        //设置RSA密钥环加密使用的私钥，解密数据前设置
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList("src/rsapri.txt")));
        //初始化加密入口
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        //加密上下文
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        //加密
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        //解密
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
    }
}
