package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @description: 文件加密
 */
public class FileEncryptionExample {

    public static void main(String[] args) throws IOException {
        //初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        /*
        *读取密钥保存在文件中的一到多个密钥，也可通过String类型密钥字符串getByte()获取，列如
            String symemetryKey1 = "I+BmZXZEftgtsDfs5YNnUg==";
            String symemetryKey2 = "fdashkjsalhfkdsahfsdkj==";
            ArrayList<byte[]> bytes = new ArrayList<>();
            bytes.add(Base64.getDecoder().decode(symemetryKey1.getBytes(StandardCharsets.UTF_8)));
            bytes.add(Base64.getDecoder().decode(symemetryKey2.getBytes(StandardCharsets.UTF_8)));
            keyring.setSymmetricKey(bytes);
        * */
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/256bit")));
        //初始化加密入口
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        //加解密上下文
        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("context", "encrypt");
        //fileInputStream 源文件对应的输入流
        //fileOutputStream 加密后文件对应的输出流
        try (FileInputStream fileInputStream = new FileInputStream("src/test.pptx");
             FileOutputStream fileOutputStream = new FileOutputStream("src/test.encrypted.pptx");) {
            //加密
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        } catch (Exception e) {
        }
        //fileInputStream 加密后文件对应的输入流
        //fileOutputStream 源文件对应的输出流
        try (FileInputStream in = new FileInputStream("src/test.encrypted.pptx");
             FileOutputStream out = new FileOutputStream("src/test.decrypted.pptx");) {
            //解密
            huaweiCrypto.decrypt(in, out);
        } catch (Exception e) {
        }


    }
}
