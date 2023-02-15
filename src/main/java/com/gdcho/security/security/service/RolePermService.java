package com.gdcho.security.security.service;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.utils.ServletUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * 自定义权限认证方法，返回布尔值
 */
@Service("rs")
public class RolePermService {

    private static final String ALL_PERMISSION = "*:*:*";

    @Autowired
    TokenService tokenService;


    public boolean hasPerm(String permission) {

        if (StrUtil.isEmpty(permission)) {
            return false;
        }

        UserPrincipal userPrincipal = tokenService.getUserPrincipal(ServletUtil.getRequest());


        if (ObjUtil.isNull(userPrincipal) || CollectionUtil.isEmpty(userPrincipal.getPermissions())) {
            return false;
        }
        return hasPermissions(userPrincipal.getPermissions(), permission);
    }

    /**
     * 验证用户是否不具备某权限，与 hasPerm逻辑相反
     *
     * @param permission 权限字符串
     * @return 用户是否不具备某权限
     */
    public boolean lacksPerm(String permission) {
        return !hasPerm(permission);
    }

    public boolean hasAnyPerm(String permissions) {

        if (StrUtil.isEmpty(permissions)) {
            return false;
        }
        UserPrincipal userPrincipal = tokenService.getUserPrincipal(ServletUtil.getRequest());

        if (ObjUtil.isNull(userPrincipal) || CollectionUtil.isEmpty(userPrincipal.getPermissions())) {
            return false;
        }

        for (String perm : permissions.split(",")) {
            if (perm != null && hasPermissions(userPrincipal.getPermissions(), perm)) {
                return true;
            }
        }
        return false;

    }


    public boolean hasPermissions(Set<String> perms,
                                  String perm) {
//        if (perms.contains(ALL_PERMISSION) ) {
//            return  true;
//        }
//        if(perms.contains(StrUtil.trim(perm))) {
//            return true;
//        }

        return perms.contains(ALL_PERMISSION) || perms.contains(StrUtil.trim(perm));
    }

}
