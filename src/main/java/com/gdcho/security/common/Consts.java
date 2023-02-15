package com.gdcho.security.common;

public interface Consts {


    /**
     *
     */
    @Deprecated
    public final String REDIS_JWT_PREFIX = "redis:jwt:";

    public final String REDIS_USER_PREFIX = "redis:user:";

    /**
     * 存储用户id的 prefix，返回用户并将此加密为jwt返回给客户端
     */
    public final String JWT_CLAIM_KEY = "login_user_id";

    /**
     * JWT请求头
     */
    public final String AUTHORIZATION_HEADER = "Authorization";

    public final String JWT_AUTHORITIES = "Authorities";

    public final String JWT_OPENID = "openId";

    public final String JWT_SESSION_KEY = "sessionKey";

    /**
     * 逻辑删除
     */
    public final Integer USER_DELETE = -1;

    /**
     * 禁用
     */
    public final Integer USER_DISABLE = 0;

    /**
     * 启用
     */
    public final Integer USER_ENABLE = 1;

    /**
     * 男性
     */
    public final Integer SEX_MALE = 1;

    /**
     * 未知性别
     */
    public final Integer SEX_UNKNOWN = 0;

    /**
     * 女性
     */
    public final Integer SEX_FEMALE = -1;

    /**
     * 小程序中验证微信服务端的请求：
     * <code>https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code</code>
     */
    public final String JS_CODE = "js_code";


    public final String MENU = "M";
    public final String BTN = "B";
}
