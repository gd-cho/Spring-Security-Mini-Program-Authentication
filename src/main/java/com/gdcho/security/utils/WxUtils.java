package com.gdcho.security.utils;

import com.gdcho.security.config.WxConfig;
import com.gdcho.security.entity.vo.WxTokenVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;


@Component
@EnableConfigurationProperties(WxConfig.class)
public class WxUtils {

    @Autowired
    WxConfig wxConfig;

    @Autowired
    RestTemplate restTemplate;

    /**
     * 通过微信服务接口，返回用户登录凭证
     *
     * @param jsCode 小程序获取jsCode后，5分钟有效
     * @return 登录凭证
     */
    public WxTokenVO getWxToken(String jsCode) {
        String code2SessionUrl = wxConfig.getCode2SessionUrl();
        String url = String.format(code2SessionUrl, wxConfig.getAppId(), wxConfig.getAppSecret(), jsCode,
                                   wxConfig.getGrantType());

        ResponseEntity<WxTokenVO> wxToken = restTemplate.getForEntity(url, WxTokenVO.class);

        return wxToken.getBody();
    }
}
