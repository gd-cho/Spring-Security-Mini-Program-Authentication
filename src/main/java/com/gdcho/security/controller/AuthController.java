package com.gdcho.security.controller;

import com.gdcho.security.common.APIResponse;
import com.gdcho.security.common.Status;
import com.gdcho.security.entity.Users;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.security.service.TokenService;
import com.gdcho.security.service.UserService;
import com.gdcho.security.utils.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("/")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;


//    @PostMapping("/login")
//    public APIResponse<JwtVO> login(@RequestBody Users users) {
//        System.out.println("login...1");
//        Authentication authenticate = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(users.getUsername(), users.getPassword()));
//        System.out.println("login...2");
//
//        SecurityContextHolder.getContext().setAuthentication(authenticate);
//        System.out.println("login...3");
//        String jwt = jwtUtil.createJWT(authenticate);
//        System.out.println("login...4");
//        return APIResponse.ofSuccess(new JwtVO(jwt));
//    }

    @PostMapping("/logout")
    public APIResponse<?> logout(HttpServletRequest request) {
        try {
            UserPrincipal userPrincipal = tokenService.getUserPrincipal(request);

            tokenService.invalidateToken(userPrincipal.getId());
            jwtUtil.invalidateJWT(request);
        } catch (SecurityException e) {
            return APIResponse.ofException(new SecurityException(Status.SC_UNAUTHORIZED));
        }

        return APIResponse.ofStatus(Status.LOGOUT);
    }


    @GetMapping("/success")
    public APIResponse<String> success() {
        return APIResponse.ofSuccess("success!!");
    }

    @PostMapping("/user/register")
    public APIResponse register(@RequestBody Users users) {
        users = userService.createUser(users.getUsername(), users.getPassword(), users.getOpenId(),
                                       users.getSessionKey());
        return APIResponse.ofSuccess(users);
    }

}
