package com.huaweicloud.encryptionsdk.model;


/**
 * DataMaterials
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
