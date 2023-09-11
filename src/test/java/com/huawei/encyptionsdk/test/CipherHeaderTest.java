package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

/**
 * @author zc
 * @ClassName CipherHeaderTest
 * @description:
 * @datetime 2022年 09月 15日 17:32
 */
public class CipherHeaderTest {

    @Test
    public void Should_ok_When_CipherHeaderVerifyTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        byte[] decode = Base64.getDecoder().decode(dataKey);
        SecretKey secretKey = Utils.byteToSecretKey(decode, "AES");
        HashMap<String, String> map = new HashMap<>();
        map.put("dsfa", "dfsf");
        ArrayList<CiphertextDataKey> list = new ArrayList<>();
        list.add(new CiphertextDataKey(new byte[] {1, 2, 3, 2, 3, 5, 6, 3, 2, 1, 2, 3, 2, 3, 5}));
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey,
            Cipher.ENCRYPT_MODE);
        CipherHeader cipherHeader = new CipherHeader(CryptoAlgorithm.AES_256_GCM_NOPADDING, map, list, secretKey);
        cipherHeader.verifyHeader(cipherHandler);
    }
}
