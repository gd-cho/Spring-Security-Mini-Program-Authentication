package com.gdcho.security.common;

import lombok.Getter;


@Getter
public enum Status {
    /**
     * 操作成功！
     */
    SUCCESS(200, "操作成功！"),

    /**
     * 操作异常！
     */
    ERROR(500, "操作异常！"),

    /**
     * 退出成功！
     */
    LOGOUT(200, "退出成功！"),

    /**
     * 请先登录！
     */
    SC_UNAUTHORIZED(401, "令牌已过期请重新登录！"),

    /**
     * 暂无权限访问！
     */
    SC_ACCESS_DENIED(403, "未授权访问此资源，如有需要请联系管理员授权！"),

    /**
     * 请求不存在！
     */
    REQUEST_NOT_FOUND(404, "请求不存在！"),

    /**
     * 请求方式不支持！
     */
    HTTP_BAD_METHOD(405, "请求方式不支持！"),

    /**
     * 请求异常！
     */
    BAD_REQUEST(400, "请求异常！"),

    /**
     * 参数不匹配！
     */
    PARAM_NOT_MATCH(400, "参数不匹配！"),

    /**
     * 参数不能为空！
     */
    PARAM_NOT_NULL(400, "参数不能为空！"),

    /**
     * 当前用户已被锁定，请联系管理员解锁！
     */
    USER_DISABLED(403, "当前用户已被锁定，请联系管理员解锁！"),

    // 账号相关

    /**
     * 用户名或密码错误！
     */
    USERNAME_PASSWORD_ERROR(5001, "用户名或密码错误！"),

    /**
     * 用户不存在
     */
    USERNAME_NOT_FOUND(5001, "用户不存在！"),

    USER_IS_EXIST(5001, "用户已存在，不得重复创建！"),

    /**
     * token 已过期，请重新登录！
     */
    TOKEN_EXPIRED(5002, "token 已过期，请重新登录！"),

    /**
     * token 解析失败，请尝试重新登录！
     */
    TOKEN_PARSE_ERROR(5002, "token 解析失败，请尝试重新登录！"),

    /**
     * 当前用户已在别处登录，请尝试更改密码或重新登录！
     */
    TOKEN_OUT_OF_CTRL(5003, "当前用户已在别处登录，请尝试更改密码或重新登录！"),

    /**
     * 无法手动踢出自己，请尝试退出登录操作！
     */
    KICKOUT_SELF(5004, "无法手动踢出自己，请尝试退出登录操作！"),

    /**
     *
     */
    SERVER_ERROR(503, "服务端出错，访问失败！"),

    // 微信相关

    /**
     * js_code无效
     */
    WX_AUTH_FAIL(40029, "js_code无效！"),
    /**
     * 微信服务：API调用频繁
     */
    WX_QUOTA_LIMIT(45011, "API调用太频繁，请稍候再试！"),
    /**
     * 微信服务：高风险用户
     */
    WX_HIGH_RISK(40226, "用户限制，小程序登录拦截！"),
    /**
     * 微信服务：系统繁忙
     */
    WX_SYS_BUSY(-1, "微信服务接口繁忙！"),
    /**
     * 微信服务：接口验证成功
     */
    WX_AUTH_SUCC(0, "接口验证成功！"),

    // 其他异常码
    OTHER_ERROR(505, "其他异常消息！");


    /**
     * 状态码
     */
    private final Integer code;

    /**
     * 返回信息
     */
    private String message;

    Status(Integer code,
           String message) {
        this.code = code;
        this.message = message;
    }

    public Status custStatusMsg(String message) {
        this.message = message;
        return this;
    }

    public static Status fromCode(Integer code) {
        Status[] statuses = Status.values();
        for (Status status : statuses) {
            if (status.getCode()
                      .equals(code)) {
                return status;
            }
        }
        return SUCCESS;
    }

    @Override
    public String toString() {
        return String.format(" Status:{code=%s, message=%s} ",
                             getCode(),
                             getMessage());
    }

}
