package com.gdcho.security.security.filter;

import cn.hutool.core.util.StrUtil;
import com.gdcho.security.common.Consts;
import com.gdcho.security.common.Status;
import com.gdcho.security.entity.vo.JwtVO;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.entity.vo.WxTokenVO;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.security.WxAuthenticationToken;
import com.gdcho.security.security.service.TokenService;
import com.gdcho.security.utils.JwtUtil;
import com.gdcho.security.utils.ResponseUtil;
import com.gdcho.security.utils.WxUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j
public class WxAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private WxUtils wxUtils;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private TokenService tokenService;


    public WxAuthenticationFilter(AuthenticationManager authenticationManager,
                                  String loginProcessingUrl) {
//        super(loginProcessingUrl);
        super(authenticationManager);
        setFilterProcessesUrl(loginProcessingUrl);
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        log.info("???WxAuthenticationFilter?????????URI???:{}", request.getRequestURI());
        //?????????????????????POST,??????GET??????????????????
        if (!"POST".equals(request.getMethod())) {
//            throw new AuthenticationServiceException("?????????POST????????????");
            ResponseUtil.renderJson(response,
                                    new SecurityException(Status.HTTP_BAD_METHOD.custStatusMsg("?????????POST???????????????")));
            return null;
        }

        // ????????????jsCode??????????????????
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String jsCode = obtainJsCode(request);

        WxAuthenticationToken unauthenticated;
        UserPrincipal.UserPrincipalBuilder userPrincipalBuilder = UserPrincipal.builder();
        // ????????????
        if (StrUtil.isNotEmpty(username) && StrUtil.isNotEmpty(password)) {
            userPrincipalBuilder.username(username).password(password);
            unauthenticated = WxAuthenticationToken.unauthenticated(userPrincipalBuilder.build());
            Authentication authenticate = getAuthenticationManager().authenticate(unauthenticated);
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            return authenticate;
        }
        // ??????????????????
        else if (StrUtil.isNotEmpty(jsCode)) {
            // ???????????????????????????????????????
            WxTokenVO wxToken = wxUtils.getWxToken(jsCode);

            String openid = wxToken.getOpenid();
            String session_key = wxToken.getSession_key();
            Integer errCode = wxToken.getErrcode();
            String errMsg;
            userPrincipalBuilder.openId(openid).sessionKey(session_key);
            if (wxToken.getErrcode() != null && !wxToken.getErrcode().equals(0)) {
                log.info("???WxAuthenticationFilter???????????????,??????????????????????????????,errCode:{},errMsg:{}",
                         wxToken.getErrcode(), wxToken.getErrmsg());

                if (errCode.equals(Status.WX_AUTH_FAIL.getCode())) {
                    errMsg = Status.WX_AUTH_FAIL.getMessage();
                } else if (errCode.equals(Status.WX_QUOTA_LIMIT.getCode())) {
                    errMsg = Status.WX_QUOTA_LIMIT.getMessage();
                } else if (errCode.equals(Status.WX_HIGH_RISK.getCode())) {
                    errMsg = Status.WX_HIGH_RISK.getMessage();
                } else if (errCode.equals(Status.WX_SYS_BUSY.getCode())) {
                    errMsg = Status.WX_SYS_BUSY.getMessage();
                } else {
                    errMsg = "????????????????????????????????????????????????";
                }
                // ????????????
                ResponseUtil.renderJson(response, new SecurityException(errCode, errMsg, null));
                return null;
            }

            unauthenticated = WxAuthenticationToken.unauthenticatedWx(userPrincipalBuilder.build());
            // ????????????
            Authentication authenticate = getAuthenticationManager().authenticate(unauthenticated);

            SecurityContextHolder.getContext().setAuthentication(authenticate);
            log.info("???WxAuthenticationFilter?????????URI???:{}", request.getRequestURI());
            return authenticate;
        } else {
            ResponseUtil.renderJson(response, Status.USERNAME_NOT_FOUND.custStatusMsg("???????????????????????????"), null);
            return null;
        }
    }

    public String obtainJsCode(HttpServletRequest request) {
        return request.getParameter(Consts.JS_CODE);
    }

    public String obtainUsername(HttpServletRequest request) {
        return request.getParameter("username");
    }

    public String obtainPassword(HttpServletRequest request) {
        return request.getParameter("password");
    }


    // ??????????????????
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
//        super.successfulAuthentication(request, response, chain, authResult);
        SecurityContextHolder.getContext().setAuthentication(authResult);
        WxAuthenticationToken wxAuthenticationToken = (WxAuthenticationToken) authResult;
        String jwt = tokenService.createJwt(wxAuthenticationToken.getUserPrincipal());
        log.info("???WxAuthenticationFilter?????????????????????????????????,??????JWT??????:{}", jwt);
        ResponseUtil.renderJson(response, Status.SUCCESS, new JwtVO(jwt));

    }

    // ??????????????????
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException ex) throws IOException, ServletException {
        log.info("???WxAuthenticationFilter?????????????????????????????????,????????????:{}", ex.getMessage());
        SecurityContextHolder.clearContext();
//        failed.printStackTrace();
        super.unsuccessfulAuthentication(request, response, ex);
        if (ex instanceof UsernameNotFoundException) {
            ResponseUtil.renderJson(response, Status.ERROR.custStatusMsg("??????????????????"), null);
        }
        if (ex instanceof LockedException) {
            ResponseUtil.renderJson(response, Status.ERROR.custStatusMsg("???????????????"), null);
        }
        if (ex instanceof BadCredentialsException) {
            ResponseUtil.renderJson(response, Status.ERROR.custStatusMsg("????????????????????????"), null);
        } else {
            ResponseUtil.renderJson(response, Status.OTHER_ERROR.custStatusMsg("???????????????"), null);
        }
    }
}