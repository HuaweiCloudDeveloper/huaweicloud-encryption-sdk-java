package com.huaweicloud.encryptionsdk.exception;

/**
 * exception
 */
public class HuaweicloudException extends RuntimeException {

    public HuaweicloudException() {
        super();
    }

    public HuaweicloudException(final String message) {
        super(message);
    }

    public HuaweicloudException(final Throwable cause) {
        super(cause);
    }

    public HuaweicloudException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
