package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.Utils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.*;

/**
 * UtilTest
 */
public class UtilTest {

    @Test
    public void Should_ok_When_IsEmptyTest() {
        boolean isEmpty;
        String str = "";
        isEmpty = Utils.isEmpty(str);
        assertTrue(isEmpty);
        Object object = null;
        isEmpty = Utils.isEmpty(object);
        assertTrue(isEmpty);
        ArrayList<Object> list = new ArrayList<>();
        isEmpty = Utils.isEmpty(list);
        assertTrue(isEmpty);
    }

    @Test
    public void Should_ok_When_ReadMasterKeyTest() {
        String originKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCDEMvyi+CkMhMfa/lCVECxMn3+2h6kf13DKH43D7osxLpeXKnZAutIvM8ulbRew0U9hvqX3XR7tKkM5K5q5qUI1vdSqUimGJmZncNPMiqxKpj6tNjpLrmgUz/Ayy1mODLkNjC400ysHUk64tvknBf2Kei1wd6XhQUfQ6eNHM+P49N8Wq/788gDbIUF0pUwuqfR+MpGdPEoSEzWFHP9hFNUXBSq9JFtT9uoGZ3/ZyG1EqLmBWnLHfv8dgd1nLBhIh/xyQz2Eax3GKABOGastQq53uM4VIAcC1RIiVdM6FBE1YNKI9j0UMTi0K6OhQ44YnRZVo0cZCinw2MI8iVlSaPRAgMBAAECggEAXg5Uvdehu1NwI7GBrBb4YfFhN93h9Zytddr+UJdJvMzlDcij3udYX9eXOtAWI5cwfkn6VbeH2yq30lfdzzt7nc9ep4RybTfkKrhrq87NklyGcgwMSbLNZX+4lat5Bg04gEtfRZPlRvKxVb/tm65lB7Plm2HoUoYUOe58NClDzvbeDHN/czJbk8EpJBi0re2czQ7NK0icS9zorhclhazssYKxBCS37cQDIgwr5+5HFIGpkZLirnB+yR+iGUelSsYLt+X+wQy+wp6ymhm0+poNOm3NbJbzmnY5b8OZJHai2k9OXVLvgA7F3IiTmZ20vG8wYkCWxX6B48jr40j/xfpMfQKBgQDam3UECjPdO4Z6asELsz93EeAVjxKUh48FQjJMOU0EYSyIGdcWDnVaiCiXq/26t0zBb7lYwNDVziD6c006UHxF7R26BGJm4pypQjTU9P4OrDd82sOn8UMi/QH/OAQNAF8KKah/o9la/EdLKS1SFtZppI1AN9/CMfm2pXXqLJ6tlwKBgQCZe/+p30P7URXggw3JtK9LXTNqIKFLDJGxjTuVhkURHNRnrHJvD46azjiG7qPzEt3pgB0+G7rGOuHLfrNBCPA8aQAMsZPAfciU1aq8Rsdab6XjL+7pvbNqlcCRsp75bM6bJ4pA3Qk86SF1zcTpvS91iEsqHvQ9bXMmV8F5ZNg21wKBgQCIIj8goOnjX2pDWa+WBa4EDFGrm0lKzZA3Ch4gcZ6Ql6MPrmfPCHn0Qs5khWqgl/1oiJa3untSaecHkD4LjouVUDAu4wQUZhKBJQWZiGed44k6a1FkiE3yv/Q6Zzu+jPiib4bK1dJJYslS+PWMJUSozRxZXXIukMidATUI+3hlSQKBgCUDt3ODKYTpWCpN0LxtO70kG+sjNWLBBD3afp0fxXZMCpl6CBrqmIyS4SUBVj6ftS7Du8mnrFJ0DtIhmx87BZy8AcwN40EP1Ji4MrW3KAqSVGJGxApQun0g4lEAz7/9UpIuZfQgmkK7QluDpVJtUo24sc/VqTdLNvLvRPR+snn/AoGAfrHketzlE6W9btyKcw7G6mf2utTdAkKaD/TFmVFCNtLc+Aw5cMlmWWhiMGP3ec0oFw9qHg1xUTdz38ThhRvThNlB/tbJbqscIfqC9+rY722GThZIl1jGCW8jR4O24lWS3jfF+B0iOdxFdTEn6bhTGtY5i4eZrqq7d44n70f3jRg=";
        List<String> strings = Collections.singletonList("src/test/resources/rsapri.txt");
        List<byte[]> bytes = Utils.readMasterKey(strings);
        assertEquals(new String(Base64.getEncoder().encode(bytes.get(0))), originKey);
    }

    @Test
    public void Should_ok_When_LongToByteTest() {
        long num = 1l;
        byte[] bytes = Utils.longToByte(num);
        long l = Utils.byteToLong(bytes);
        assertEquals(num, l);
    }

    @Test
    public void Should_ok_When_AddPreventOverFlowTest() {
        long num = 1l;
        long num1 = 2l;
        long numMax = Long.MAX_VALUE;
        long numMin = Long.MIN_VALUE;
        long num4 = -1l;

        long result = Utils.addPreventOverFlow(num, num1);
        assertEquals(result, num + num1);

        long result2 = Utils.addPreventOverFlow(num, numMax);
        assertEquals(result2, numMax);

        long result3 = Utils.addPreventOverFlow(numMin, num4);
        assertEquals(result3, numMin);

    }

    @Test
    public void Should_ok_When_CommonHashTest() {
        byte[] bytes = Utils.commonHash("test".getBytes(StandardCharsets.UTF_8), "SM3");
        assertNotNull(bytes);
    }

    @Test
    public void Should_ok_When_SerializeTest() {
        HashMap<String, String> map = new HashMap<>();
        map.put("key", "value");
        map.put("1", "2");
        byte[] bytes = Utils.serializeContext(map);
        assertNotNull(bytes);
        Map<String, String> deserializeContext = Utils.deserializeContext(bytes);
        assertEquals(map, deserializeContext);
    }


}
