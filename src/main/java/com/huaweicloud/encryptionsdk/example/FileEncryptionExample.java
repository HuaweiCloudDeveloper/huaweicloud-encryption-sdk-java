package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.util.CommonUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Collections;
import java.util.Map;

/**
 * @description: 文件加密
 */
public class FileEncryptionExample {

    public static void main(String[] args) {
        // 初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        /**
         * 读取密钥保存在文件中的一到多个密钥，也可通过String类型密钥字符串getByte()获取，列如
         * String symemetryKey1 = "I+BmZXZEftgtsDfs5YNnUg==";
         * String symemetryKey2 = "fdashkjsalhfkdsahfsdkj==";
         * ArrayList<byte[]> bytes = new ArrayList<>();
         * bytes.add(Base64.getDecoder().decode(symemetryKey1.getBytes(StandardCharsets.UTF_8)));
         * bytes.add(Base64.getDecoder().decode(symemetryKey2.getBytes(StandardCharsets.UTF_8)));
         * keyring.setSymmetricKey(bytes);
         */
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_256_FILE_PATH)));
        // 初始化加密入口
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        // fileInputStream 源文件对应的输入流
        // fileOutputStream 加密后文件对应的输出流
        try (FileInputStream fileInputStream = new FileInputStream(FilePathForExampleConstants.TEST_PPT_FILE_PATH);
            FileOutputStream fileOutputStream = new FileOutputStream(FilePathForExampleConstants.ENCRYPTED_TXT_FILE_PATH)) {
            // 加密
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        } catch (Exception e) {
        }
        // fileInputStream 加密后文件对应的输入流
        // fileOutputStream 源文件对应的输出流
        try (FileInputStream in = new FileInputStream(FilePathForExampleConstants.ENCRYPTED_TXT_FILE_PATH);
            FileOutputStream out = new FileOutputStream("src/test.decrypted.pptx")) {
            // 解密
            huaweiCrypto.decrypt(in, out);
        } catch (Exception e) {
        }

    }
}
