package com.huaweicloud.encryptionsdk.model;

/**
 * @author zc
 * @ClassName DataMaterials
 * @description:
 * @datetime 2022年 09月 15日 10:32
 */
public class DataMaterials {
    private CipherBody cipherBody;

    private CipherHeader headers;

    public DataMaterials(CipherBody cipherBody, CipherHeader headers) {
        this.cipherBody = cipherBody;
        this.headers = headers;
    }

    public CipherBody getCipherBody() {
        return cipherBody;
    }

    public void setCipherBody(CipherBody cipherBody) {
        this.cipherBody = cipherBody;
    }

    public CipherHeader getHeaders() {
        return headers;
    }

    public void setHeaders(CipherHeader headers) {
        this.headers = headers;
    }
}
