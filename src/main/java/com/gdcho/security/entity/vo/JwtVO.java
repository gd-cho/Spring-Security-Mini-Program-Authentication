package com.gdcho.security.entity.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtVO {
    /**
     * token 字段
     */
    private String token;
    /**
     * token类型
     */
    private String tokenType = "Bearer";

    public JwtVO(String token) {
        this.token = token;
    }
}