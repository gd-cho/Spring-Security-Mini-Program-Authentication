package com.gdcho.security.entity.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class WxTokenVO {

    private String session_key;

    private String unionid;

    private String openid;

    private Integer errcode;

    private String errmsg;

}
