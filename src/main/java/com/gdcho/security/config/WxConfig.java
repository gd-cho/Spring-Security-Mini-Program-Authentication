package com.gdcho.security.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "wx")
@Data
public class WxConfig {
    @Value("app-id")
    private String appId;

    @Value("app-secret")
    private String appSecret;

    @Value("grant-type")
    private String grantType = "authorization_code";

    private String code2SessionUrl = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=%s";
}
