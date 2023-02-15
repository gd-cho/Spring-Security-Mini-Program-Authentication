package com.gdcho.security.config;

import com.gdcho.security.entity.vo.WxTokenVO;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;

class WxAuthenticationFilterTest {

    private String code2SessionUrl = "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=%s";
    private String code2SessionUrl2 = "https://api.weixin.qq.com/sns/jscode2session?appid={appid}&secret={secret}&js_code={js_code}&grant_type={grant_type}";

    private String appId = "wx1751bf3234921bde";

    private String appSecret = "5e70d3f8253bf8f3be4104486226ae70";

    private final String grantType = "authorization_code";

    @Test
    public void getWxToken() {
        String jsCode = "031zJj0w33I8503ZHE3w3AkMhV1zJj0L";

//        WxTokenVO wxTokenVO = new WxTokenVO();
        RestTemplate rest = new RestTemplate();
        String url = String.format(code2SessionUrl, appId, appSecret, jsCode, grantType);
        HashMap<String, Object> params = new HashMap();
//        ?appid=%s&secret=%s&js_code=%s&grant_type=%s
        params.put("appid", appId);
        params.put("secret", appSecret);
        params.put("js_code", jsCode);
        params.put("grant_type", grantType);
        MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
        mappingJackson2HttpMessageConverter.setSupportedMediaTypes(
                Arrays.asList(MediaType.TEXT_HTML, MediaType.TEXT_PLAIN));
        rest.getMessageConverters().add(mappingJackson2HttpMessageConverter);
        ResponseEntity<WxTokenVO> forObject = rest.getForEntity(url, WxTokenVO.class);

        System.out.println("forObject.getStatusCode() = " + forObject.getStatusCode());
        System.out.println("forObject.getHeaders() = " + forObject.getHeaders());
        System.out.println("forObject.getBody() = " + forObject.getBody());
    }
}