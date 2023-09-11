package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.handler.DefaultCryptoHandler;
import com.huaweicloud.encryptionsdk.handler.FileDecryptHandler;
import com.huaweicloud.encryptionsdk.handler.FileEncryptHandler;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author zc
 * @ClassName DefaultCryptoHandlerTest
 * @description:
 * @datetime 2022年 09月 23日 14:35
 */
public class CryptoHandlerTest {

    private final byte[] plaintText = "hello world".getBytes(StandardCharsets.UTF_8);

    @Test
    public void Should_ok_When_CryptoHandlerData() throws NoSuchAlgorithmException, NoSuchProviderException {
        DefaultCryptoHandler defaultCryptoHandler = new DefaultCryptoHandler();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        List<byte[]> bytes = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH));
        SecretKey secretKey = new SecretKeySpec(bytes.get(0), "SM4");
        dataKeyMaterials.setPlaintextDataKey(secretKey);
        CryptoResult<byte[]> encrypt = defaultCryptoHandler.encrypt(
            new EncryptRequest(Collections.emptyMap(), "hello world".getBytes(StandardCharsets.UTF_8)),
            dataKeyMaterials);
        CryptoResult<byte[]> decrypt = defaultCryptoHandler.decrypt(encrypt.getResult(), dataKeyMaterials);
        Assert.assertEquals(new String(decrypt.getResult()), "hello world");
    }

    @Test
    public void Should_ok_When_CipherHandlerCipherData() {
        List<byte[]> bytes = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH));
        SecretKey secretKey = new SecretKeySpec(bytes.get(0), "SM4");
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.ENCRYPT_MODE);
        byte[] encryptData = cipherHandler.cipherData(plaintText, Collections.emptyMap(), 0, plaintText.length);
        byte[] iv = cipherHandler.getIv();
        byte[] result = new byte[encryptData.length + iv.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptData, 0, result, iv.length, encryptData.length);
        cipherHandler.setMode(Cipher.DECRYPT_MODE);
        byte[] decryptData = cipherHandler.cipherData(result, Collections.emptyMap(), iv.length, encryptData.length);
        Assert.assertEquals(new String(decryptData, StandardCharsets.UTF_8),
            new String(plaintText, StandardCharsets.UTF_8));
    }

    @Test
    public void Should_ok_When_CipherHandlerProcessData() {
        List<byte[]> bytes = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH));
        SecretKey secretKey = new SecretKeySpec(bytes.get(0), "SM4");
        FileEncryptHandler cipherHandler = new FileEncryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.ENCRYPT_MODE);
        try (InputStream inputStreamEncrypt = new FileInputStream(FilePathForExampleConstants.BIT_128_FILE_PATH);
            FileOutputStream outputStreamEncrypt = new FileOutputStream("src/test/resources/128bit.encrypted")) {
            cipherHandler.processByte(inputStreamEncrypt, outputStreamEncrypt, Collections.emptyMap(), 4096);
        } catch (Exception e) {
            e.printStackTrace();
        }

        FileDecryptHandler fileDecryptHandler = new FileDecryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.DECRYPT_MODE);

        try (FileInputStream fileInputStream = new FileInputStream("src/test/resources/128bit.encrypted");
            FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/128bit.decrypted");) {
            fileDecryptHandler.processByte(fileInputStream, fileOutputStream, Collections.emptyMap(), 4096);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_Exception_When_EncryptedFileChanged() throws IOException {
        List<byte[]> bytes = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH));
        SecretKey secretKey = new SecretKeySpec(bytes.get(0), "SM4");
        FileEncryptHandler cipherHandler = new FileEncryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.ENCRYPT_MODE);
        try (InputStream inputStreamEncrypt = Files.newInputStream(Paths.get(FilePathForExampleConstants.BIT_128_FILE_PATH));
            FileOutputStream outputStreamEncrypt = new FileOutputStream("src/test/resources/128bit.encrypted")) {
            cipherHandler.processByte(inputStreamEncrypt, outputStreamEncrypt, Collections.emptyMap(), 4096);
        } catch (Exception e) {
            e.printStackTrace();
        }

        changeFile();
        FileDecryptHandler fileDecryptHandler = new FileDecryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.DECRYPT_MODE);
        try (FileInputStream fileInputStream = new FileInputStream("src/test/resources/128bit.encrypted");
            FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/128bit.decrypted");) {
            fileDecryptHandler.processByte(fileInputStream, fileOutputStream, Collections.emptyMap(), 4096);
        }
    }

    private void changeFile() {
        try (FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/128bit.encrypted", true)) {
            fileOutputStream.write(1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_Exception_When_EncryptionContextNotEqual() throws IOException {
        List<byte[]> bytes = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH));
        SecretKey secretKey = new SecretKeySpec(bytes.get(0), "SM4");
        FileEncryptHandler cipherHandler = new FileEncryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.ENCRYPT_MODE);
        try (InputStream inputStreamEncrypt = new FileInputStream(FilePathForExampleConstants.BIT_128_FILE_PATH);
            FileOutputStream outputStreamEncrypt = new FileOutputStream("src/test/resources/128bit.encrypted")) {
            cipherHandler.processByte(inputStreamEncrypt, outputStreamEncrypt, Collections.emptyMap(), 1024);
        }

        FileDecryptHandler fileDecryptHandler = new FileDecryptHandler(CryptoAlgorithm.SM4_128_GCM_NOPADDING, secretKey,
            Cipher.DECRYPT_MODE);
        try (FileInputStream fileInputStream = new FileInputStream("src/test/resources/128bit.encrypted");
            FileOutputStream fileOutputStream = new FileOutputStream("src/test/resources/128bit.decrypted")) {
            Map<String, String> map = new HashMap<>();
            map.put("key", "value");
            fileDecryptHandler.processByte(fileInputStream, fileOutputStream, map, 1024);
        }
    }

}
