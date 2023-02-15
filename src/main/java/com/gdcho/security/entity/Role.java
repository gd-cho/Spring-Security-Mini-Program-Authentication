package com.gdcho.security.entity;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import lombok.*;
import org.hibernate.Hibernate;

import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
@Entity
@AllArgsConstructor
public class Role extends BaseEntity {
    /**
     * 角色名称
     */
    @Column(name = "role_name",
            unique = true)
    private String name;

    @ManyToMany(mappedBy = "role")
    @ToString.Exclude
    private Set<Users> users;

    @Column(name = "role_desc")
    private String roleDesc;

    /**
     * 角色状态：1正常，0停用
     */
    @Column(columnDefinition = "tinyint")
    private Integer status;

    /**
     * 菜单/按钮URL
     */
    private String url;

    /**
     * 类型：B按钮、P页面
     */
    private String type;

    /**
     * 权限字符串
     * 一般格式为：${达模块}:${小模块}:{操作}
     * 超级管理员：*:*:*
     * 拥有小模块的所有操作权限：sys:user:*
     * <p>
     * 带多个权限使用逗号分隔
     * 如：sys:user:query,sys:user:add
     */
    @Column(name = "role_perms")
    private String perms;


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        Role role = (Role) o;
        return getId() != null && Objects.equals(getId(), role.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
