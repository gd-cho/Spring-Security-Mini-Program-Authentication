package com.gdcho.security.security.filter;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.StrUtil;
import com.gdcho.security.common.Status;
import com.gdcho.security.entity.Users;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.exception.BaseException;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.security.WxAuthenticationToken;
import com.gdcho.security.security.service.TokenService;
import com.gdcho.security.service.UserService;
import com.gdcho.security.utils.JwtUtil;
import com.gdcho.security.utils.ResponseUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
public class WxJwtAuthenticationFilter extends OncePerRequestFilter {


    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

//    public WxJwtAuthenticationFilter(AuthenticationManager authenticationManager) {
//        super(authenticationManager);
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        log.info("【WxJwtAuthenticationFilter】处理JWT验证中, 请求URI:{}", request.getRequestURI());

        try {
            // 从jwt解析userid，根据userid在redis查找userPrincipal
            UserPrincipal userPrincipal = tokenService.getUserPrincipal(request);
            if (userPrincipal != null) {
                // 查询用户
                Optional<Users> ouser = userService.queryUserById(userPrincipal.getId());
                if (ouser.isEmpty()) {
                    // 用户不存在
                    throw new SecurityException(Status.USERNAME_NOT_FOUND);
                }
                Users user = ouser.get();
                BeanUtil.copyProperties(user, userPrincipal);
                System.out.println("WxJwtAuthenticationFilter.userPrincipal = " + userPrincipal);
                WxAuthenticationToken authenticated;
                // 验证令牌是否快要过期，快过期则更新
                tokenService.verifyTokenExpire(userPrincipal);

                userService.updateUser(user);

                // 是否有登录账号秘密
                if (StrUtil.isAllNotEmpty(userPrincipal.getUsername(), userPrincipal.getPassword())) {
                    authenticated = WxAuthenticationToken.authenticated(userPrincipal, null);
                } else {
                    authenticated = WxAuthenticationToken.authenticatedWx(userPrincipal, null);
                }
                log.debug("WxJwtAuthenticationFilter】Security Context Authentication已填充,userId:{}",
                          userPrincipal.getId());

                SecurityContextHolder.getContext().setAuthentication(authenticated);
            } else {
                log.info("【WxJwtAuthenticationFilter】Token不存在,进入下一个过滤器");
            }
            filterChain.doFilter(request, response);
        } catch (RuntimeException e) {
            if (e instanceof SecurityException) {
                ResponseUtil.renderJson(response, (BaseException) e);
            } else {
                e.printStackTrace();
                ResponseUtil.renderJson(response, Status.OTHER_ERROR.getCode(), "其他错误触发！", null);
            }
        }
    }

}
