package com.gdcho.security.common;

import com.gdcho.security.exception.BaseException;
import lombok.Data;

import java.io.Serializable;

/**
 * <p>
 * 通用的 API 接口封装
 * </p>
 */
@Data
public class APIResponse<T> implements Serializable {
    private static final long serialVersionUID = 8993485788201922830L;

    /**
     * 状态码
     */
    private Integer code;

    /**
     * 返回内容
     */
    private String message;

    /**
     * 返回数据
     */
    private T data;

    /**
     * 无参构造函数
     */
    private APIResponse() {

    }

    /**
     * 全参构造函数
     *
     * @param code    状态码
     * @param message 返回内容
     * @param data    返回数据
     */
    private APIResponse(Integer code,
                        String message,
                        T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    /**
     * 构造一个自定义的API返回
     *
     * @param code    状态码
     * @param message 返回内容
     * @param data    返回数据
     * @return ApiResponse
     */
    public static <T> APIResponse<T> of(Integer code,
                                        String message,
                                        T data) {
        return new APIResponse<T>(code,
                                  message,
                                  data);
    }

    /**
     * 构造一个成功且不带数据的API返回
     *
     * @return ApiResponse
     */
    public static APIResponse<?> ofSuccess() {
        return ofSuccess(null);
    }

    /**
     * 构造一个成功且带数据的API返回
     *
     * @param data 返回数据
     * @return ApiResponse
     */
    public static <T> APIResponse<T> ofSuccess(T data) {
        return ofStatus(Status.SUCCESS,
                        data);
    }

    /**
     * 构造一个成功且自定义消息的API返回
     *
     * @param message 返回内容
     * @return ApiResponse
     */
    public static APIResponse<?> ofMessage(String message) {
        return of(Status.SUCCESS.getCode(),
                  message,
                  null);
    }

    /**
     * 构造一个有状态的API返回
     *
     * @param status 状态 {@link Status}
     * @return ApiResponse
     */
    public static APIResponse<?> ofStatus(Status status) {
        return ofStatus(status,
                        null);
    }

    /**
     * 构造一个有状态且带数据的API返回
     *
     * @param status 状态 {@link Status}
     * @param data   返回数据
     * @return ApiResponse
     */
    public static <T> APIResponse<T> ofStatus(Status status,
                                              T data) {
        return of(status.getCode(),
                  status.getMessage(),
                  data);
    }

    /**
     * 构造一个异常的API返回
     *
     * @param t   异常
     * @param <T> {@link BaseException} 的子类
     * @return ApiResponse
     */
    public static <T extends BaseException> APIResponse<?> ofException(T t) {
        return of(t.getCode(),
                  t.getMessage(),
                  t.getData());
    }
}