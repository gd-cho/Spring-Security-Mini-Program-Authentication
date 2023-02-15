package com.gdcho.security.handler;

import com.gdcho.security.common.Status;
import com.gdcho.security.entity.vo.JwtVO;
import com.gdcho.security.security.WxAuthenticationToken;
import com.gdcho.security.security.service.TokenService;
import com.gdcho.security.utils.JwtUtil;
import com.gdcho.security.utils.ResponseUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class WxAuthSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private TokenService tokenService;

    public WxAuthSuccessHandler(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        WxAuthenticationToken wxAuthenticationToken = (WxAuthenticationToken) authentication;
        String jwt = tokenService.createJwt(wxAuthenticationToken.getUserPrincipal());
        ResponseUtil.renderJson(response, Status.SUCCESS, new JwtVO(jwt));
    }
}
