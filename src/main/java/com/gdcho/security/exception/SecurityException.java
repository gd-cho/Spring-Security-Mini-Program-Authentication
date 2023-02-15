package com.gdcho.security.exception;

import com.gdcho.security.common.Status;

public class SecurityException extends BaseException {

    public SecurityException(Status status) {
        super(status);
    }

    public SecurityException(Status status,
                             Object data) {
        super(status,
              data);
    }

    public SecurityException(Integer code,
                             String message,
                             Object data) {
        super(code,
              message,
              data);
    }
}
