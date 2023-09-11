package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiCrypto;

/**
 * @description: 本地非对称主密钥RSA密钥环简单加解密
 */
public class LocalRSAKeyringEncryptionExample {

    private static final String PLAIN_TEXT = "Hello World!";

    public static void main(String[] args) {
        HuaweiCrypto huaweiCrypto = EncryptCodeExtract.getHuaweiCrypto();
        EncryptCodeExtract.encrypt(huaweiCrypto);
    }

}
