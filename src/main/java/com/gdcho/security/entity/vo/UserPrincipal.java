package com.gdcho.security.entity.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Set;

@Data
@NoArgsConstructor
@Builder
@AllArgsConstructor
/**
 * 用于
 */
public class UserPrincipal implements Serializable {

    @Serial
    private static final long serialVersionUID = -1;

    private Long id;

    private String username;

    private String nickname;

    private String password;

    private String phone;

    private Integer sex;

    private Integer status;

    private Date createTime;

    private Date lastUpdateTime;

    private Date lastLoginTime;

    private String openId;

    private String unionId;

    private String sessionKey;

    private Long expireTime;

    private Set<String> permissions;

}
