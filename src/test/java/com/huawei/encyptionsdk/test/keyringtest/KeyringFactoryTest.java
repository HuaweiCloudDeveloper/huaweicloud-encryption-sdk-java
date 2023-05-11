package com.huawei.encyptionsdk.test.keyringtest;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import org.apache.commons.codec.DecoderException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

/**
 * KeyringFactoryTest
 */
public class KeyringFactoryTest {

    @Test
    public void createKeyring() {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring sM2 = rawKeyringFactory.getKeyring("sM2");
        sM2.setPublicKey("sdfs".getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals("sdfs", new String(sM2.getPublicKey().get(0)));
    }

    @Test(expected = KeyringNotFoundException.class)
    public void Should_Exception_When_ErrorTypeKeyringTest() {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring sM2 = rawKeyringFactory.getKeyring("333");
        sM2.setPublicKey("sdfs".getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals("sdfs", new String(sM2.getPublicKey().get(0)));
    }


    @Test(expected = KeyringNotFoundException.class)
    public void Should_Exception_When_NoKeyringTest() throws DecoderException, NoSuchAlgorithmException, IOException {
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(new HuaweiConfig());
        huaweiCrypto.encrypt("test".getBytes(StandardCharsets.UTF_8));
    }
}
