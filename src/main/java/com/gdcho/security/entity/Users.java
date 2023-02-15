package com.gdcho.security.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.Hibernate;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.lang.Nullable;

import java.util.Date;
import java.util.Objects;
import java.util.Set;

@Entity
@Getter
@Setter
@RequiredArgsConstructor
@Builder
@Table(name = "users")
//@NoArgsConstructor
@AllArgsConstructor
@DynamicInsert
@DynamicUpdate
@ToString(callSuper = true)
public class Users extends BaseEntity {

    /**
     * 用户名
     */
    @Column(name = "username",
            unique = true)
    private String username;

    /**
     * 昵称
     */
    private String nickname;

    /**
     * 加密后的密码
     */
    private String password;

    /**
     * 手机号码
     */
    @Column(length = 11)
    private String phone;

    /**
     * 状态，-1：逻辑删除，0：禁用，1：启用
     */
    @Column(columnDefinition = "tinyint")
    private Integer status;

    /**
     * 上次登录时间
     */
    @Column(name = "last_login_time")
    private Date lastLoginTime;

    /**
     * 性别
     */
    @Column(columnDefinition = "tinyint")
    private Integer sex;

    /**
     * 微信相关：微信小程序用户唯一 openId
     */
    private String openId;

    /**
     * 微信相关：微信开放平台用户唯一 unionId
     */
    private String unionId;

    /**
     * sessionKey
     */
    private String sessionKey;


    @ManyToMany(cascade = CascadeType.ALL,
                fetch = FetchType.EAGER)
    @JoinTable(name = "users_role",
               joinColumns = @JoinColumn(name = "users_id",
                                         referencedColumnName = "id"),
               inverseJoinColumns = @JoinColumn(name = "role_id",
                                                referencedColumnName = "id"))
    @Nullable
    private Set<Role> role;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        Users users = (Users) o;
        return getId() != null && Objects.equals(getId(), users.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}