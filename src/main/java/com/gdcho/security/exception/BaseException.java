package com.gdcho.security.exception;


import com.gdcho.security.common.Status;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class BaseException extends RuntimeException {
    private Integer code;

    private String message;

    private Object data;

    public BaseException(Status status) {
        this.code = status.getCode();
        this.message = status.getMessage();
    }

    public BaseException(Status status,
                         Object data) {
        this(status);
        this.data = data;
    }

    public BaseException(Integer code,
                         String message) {

        this.code = code;
        this.message = message;
    }

    public BaseException(Integer code,
                         String message,
                         Object data) {
        this.message = message;
        this.code = code;
        this.data = data;
    }
}
