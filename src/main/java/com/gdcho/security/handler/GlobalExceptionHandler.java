package com.gdcho.security.handler;

import cn.hutool.json.JSONUtil;
import com.gdcho.security.common.APIResponse;
import com.gdcho.security.common.Status;
import com.gdcho.security.exception.BaseException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    @ResponseBody
    public APIResponse<?> handleException(Exception ex) {
        if (ex instanceof BaseException) {
            log.error("【全局异常拦截】BaseException，错误码：{}，错误消息：{}", ((BaseException) ex).getCode(),
                      ex.getMessage());
            return APIResponse.ofException((BaseException) ex);
        } else if (ex instanceof HttpRequestMethodNotSupportedException) {
            log.error("【全局异常拦截】HttpRequestMethodNotSupportedException，当前请求方式：{}，支持请求方式：{}",
                      ((HttpRequestMethodNotSupportedException) ex).getMethod(),
                      JSONUtil.toJsonStr(((HttpRequestMethodNotSupportedException) ex).getSupportedMethods()));
            return APIResponse.ofStatus(Status.HTTP_BAD_METHOD);
        } else if (ex instanceof MethodArgumentNotValidException) {
            log.error("【全局异常拦截】MethodArgumentNotValidException", ex);
            return APIResponse.of(Status.BAD_REQUEST.getCode(),
                                  ((MethodArgumentNotValidException) ex).getBindingResult().getAllErrors().get(0)
                                                                        .getDefaultMessage(), null);
        } else if (ex instanceof ConstraintViolationException) {
            log.error("【全局异常拦截】ConstraintViolationException", ex);
            return APIResponse.of(Status.BAD_REQUEST.getCode(), ((ConstraintViolationException) ex).getConstraintName(),
                                  null);
        } else if (ex instanceof MethodArgumentTypeMismatchException) {
            log.error("【全局异常拦截】MethodArgumentTypeMismatchException: 参数名 {}, 异常信息 {}",
                      ((MethodArgumentTypeMismatchException) ex).getName(), ex.getMessage());
            return APIResponse.ofStatus(Status.PARAM_NOT_MATCH);
        } else if (ex instanceof HttpMessageNotReadableException) {
            log.error("【全局异常拦截】HttpMessageNotReadableException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.PARAM_NOT_NULL);
        } else if (ex instanceof BadCredentialsException) {
            log.error("【全局异常拦截】BadCredentialsException: 错误信息 {}", ex.getMessage());
        } else if (ex instanceof DisabledException) {
            log.error("【全局异常拦截】DisabledException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.USER_DISABLED);
        } else if (ex instanceof NoHandlerFoundException) {
            log.error("【全局异常拦截】NoHandlerFoundException: 错误码 {}, 错误信息 {}",
                      ((NoHandlerFoundException) ex).getStatusCode(), ex.getMessage());
            return APIResponse.ofStatus(Status.REQUEST_NOT_FOUND);
        } else if (ex instanceof AccessDeniedException) {
            log.error("【全局异常拦截】AccessDeniedException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.SC_ACCESS_DENIED);
        }

        log.error("【全局异常拦截】: 异常信息 {} ", ex.getMessage());
        ex.printStackTrace();
        return APIResponse.ofStatus(Status.OTHER_ERROR.custStatusMsg(ex.getMessage()));
    }
}
