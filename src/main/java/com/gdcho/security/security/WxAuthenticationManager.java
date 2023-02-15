package com.gdcho.security.security;

import cn.hutool.core.bean.BeanUtil;
import com.gdcho.security.common.Status;
import com.gdcho.security.entity.Role;
import com.gdcho.security.entity.Users;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.security.service.TokenService;
import com.gdcho.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Component
public class WxAuthenticationManager implements AuthenticationManager {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        WxAuthenticationToken wxAuthenticationToken = null;
        if (!(authentication instanceof WxAuthenticationToken)) {
            return null;
        }

        wxAuthenticationToken = (WxAuthenticationToken) authentication;
        UserPrincipal userPrincipal = new UserPrincipal();
        // 判断是不是普通登录
        if (!wxAuthenticationToken.isWx()) {

            String username = wxAuthenticationToken.getUserPrincipal().getUsername();
            String password = wxAuthenticationToken.getUserPrincipal().getPassword();
            Optional<Users> ouser = userService.queryUserByUsername(username);
            // 用户不存在
            if (ouser.isEmpty()) {
                // 抛出用户名密码错误
                log.debug("【WxAuthenticationManager】用户不存在，请先注册");
                throw new SecurityException(Status.USERNAME_NOT_FOUND);
            } else {
                Users user = ouser.get();
                String presentedPassword = user.getPassword();
                if (!bCryptPasswordEncoder.matches(password, presentedPassword)) {
                    log.debug("【WxAuthenticationManager】用户名密码登录失败，账号或密码错误");
                    throw new SecurityException(Status.USERNAME_PASSWORD_ERROR);
                }
                BeanUtil.copyProperties(user, userPrincipal);
                Set<String> rolePerms = getUserRolePerms(user);
                userPrincipal.setPermissions(rolePerms);
                // 验证令牌是否快要过期，快过期则更新
                tokenService.verifyTokenExpire(userPrincipal);

                userService.updateUser(user);
                System.out.println("WxAuthenticationManager.userPrincipal for Login = " + userPrincipal);
                return WxAuthenticationToken.authenticated(userPrincipal, null);
            }
        } else {
            // 微信登录处理
            String openId = wxAuthenticationToken.getUserPrincipal().getOpenId();
            String sessionKey = wxAuthenticationToken.getUserPrincipal().getSessionKey();
            Optional<Users> ouser = userService.queryUserByOpenId(openId);
            Users user;
            // 用户不存在，进行注册
            if (ouser.isEmpty()) {
                // 存储到数据库
                user = userService.createUser(null, null, openId, sessionKey);
                log.debug("【WxAuthenticationManager】微信登录，用户不存在，已注册用户:{}", user);
                BeanUtil.copyProperties(user, userPrincipal);
            }
            // 用户存在，更新登录等数据
            else {
                user = ouser.get();
                BeanUtil.copyProperties(user, userPrincipal);
                // 验证令牌是否快要过期，快过期则更新
                tokenService.verifyTokenExpire(userPrincipal);
                userService.updateUser(user);
            }

            Set<String> rolePerms = getUserRolePerms(user);
            // 设置权限
            userPrincipal.setPermissions(rolePerms);
            // 验证令牌是否快要过期，快过期则更新
            tokenService.verifyTokenExpire(userPrincipal);
            System.out.println("WxAuthenticationManager.userPrincipal for WX = " + userPrincipal);
            return WxAuthenticationToken.authenticatedWx(userPrincipal, null);
        }

    }

    public Set<String> getUserRolePerms(Users user) {
        Set<String> perms = new HashSet<String>();
        if (user.getRole() == null) {
            return null;
        }
        for (Role role : user.getRole()) {
            perms.addAll(Arrays.asList(role.getPerms().split(",")));
        }
        return perms;
    }

}
