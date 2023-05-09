package com.huaweicloud.encryptionsdk.exception;


public class CipherTamperedException extends HuaweicloudException {
    public CipherTamperedException() {
        super();
    }

    public CipherTamperedException(final String message) {
        super(message);
    }

    public CipherTamperedException(final Throwable cause) {
        super(cause);
    }

    public CipherTamperedException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
