package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import org.junit.Test;

public class HuaweiConfigTest {

    @Test
    public void Should_ok_When_StateUnderTest() {
        HuaweiConfig build = HuaweiConfig.builder().ak("2").sk("2").build();
    }
}
