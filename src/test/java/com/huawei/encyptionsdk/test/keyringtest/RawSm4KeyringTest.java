package com.huawei.encyptionsdk.test.keyringtest;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;

/**
 * RawAesKeyringTest
 */
public class RawSm4KeyringTest {
    @Test
    public void Should_ok_When_StateUnderSM4EncryptTest() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "AES"));
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_gcm");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/128bit")));
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        keyring.encryptDataKey(dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getCiphertextDataKeys().get(0).getDataKey()));
        dataKeyMaterials.setPlaintextDataKey(null);
        keyring.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(dataKey,encodedKey);
    }


    @Test
    public void Should_ok_When_StateUnderSM4CBCEncryptTest() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "AES"));
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_cbc");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList("src/test/resources/128bit")));
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_CBC_PADDING);
        keyring.encryptDataKey(dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getCiphertextDataKeys().get(0).getDataKey()));
        dataKeyMaterials.setPlaintextDataKey(null);
        keyring.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(encodedKey, dataKey);
    }
}
