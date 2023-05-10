package com.huawei.encyptionsdk.test;


import com.huaweicloud.encryptionsdk.HuaweiConfig;
import org.junit.Assert;
import org.junit.Test;

public class HuaweiConfigTest {

    @Test
    public void Should_ok_When_StateUnderTest() {
        HuaweiConfig build = HuaweiConfig.builder().buildAk("2").buildSk("2").build();
    }
}
