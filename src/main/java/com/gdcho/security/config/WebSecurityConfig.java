package com.gdcho.security.config;

import com.gdcho.security.common.Status;
import com.gdcho.security.security.WxAuthenticationManager;
import com.gdcho.security.security.filter.WxAuthenticationFilter;
import com.gdcho.security.security.filter.WxJwtAuthenticationFilter;
import com.gdcho.security.utils.JwtUtil;
import com.gdcho.security.utils.ResponseUtil;
import com.gdcho.security.utils.WxUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Slf4j
public class WebSecurityConfig {

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    WxUtils wxUtils;

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    private WxAuthenticationManager wxAuthenticationManager;

    /**
     * @param http http相关的配置
     * @return
     * @throws Exception
     */
    @Bean
    @SuppressWarnings("all")
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 禁用默认的JSP表单登录
//        http.formLogin(form -> form.loginPage("/login"));
//        http.logout(logout -> logout.logoutSuccessUrl("/success"));

        // 插入自定义登录过滤器
        http.addFilter(wxAuthenticationFilter());

        // 插入JWT认证过滤器，在登录认证过滤器之前
        http.addFilterBefore(wxJwtAuthenticationFilter(), WxAuthenticationFilter.class);

        // 开启匿名认证
        http.anonymous();

        // 禁用Basic认证
        http.httpBasic().disable();

        // 验证路径
        http.authorizeHttpRequests().requestMatchers("/", "/user/register").permitAll().and()
            .authorizeHttpRequests().anyRequest().authenticated();

        // 设置session无状态
        http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 设置未授权请求异常处理
        http.exceptionHandling(
                e -> e.accessDeniedHandler(accessDeniedHandler()).authenticationEntryPoint(authenticationEntryPoint()));

        http.csrf().disable();

        return http.build();
    }

    @Bean
    public WxAuthenticationFilter wxAuthenticationFilter() throws Exception {
        WxAuthenticationFilter wxAuthenticationFilter = new WxAuthenticationFilter(
                wxAuthenticationManager, "/user/login");

//        wxAuthenticationFilter.setAuthenticationManager(wxAuthenticationManager);

        // 通过类来定义成功或失败的处理
//        wxAuthenticationFilter.setAuthenticationSuccessHandler(new WxAuthSuccessHandler(jwtUtil));
//        wxAuthenticationFilter.setAuthenticationFailureHandler(new WxAuthFailureHandler());

        return wxAuthenticationFilter;
    }

    @Bean
    public WxJwtAuthenticationFilter wxJwtAuthenticationFilter() throws Exception {
        return new WxJwtAuthenticationFilter();
    }


    @Bean
    // 权限异常：登录成功。但无权限
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            System.out.println("【AccessDeniedHandler】异常:" + accessDeniedException);
            ResponseUtil.renderJson(response, Status.SC_ACCESS_DENIED.getCode(),
                                    "未授权访问此资源，如有需要请联系管理员授权！",
                                    accessDeniedException.getMessage());
        };
    }

    @Bean
    // 认证异常：登录失败。
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            System.out.println("【AuthenticationEntryPoint】异常:" + authException.getMessage());
//            authException.printStackTrace();
            ResponseUtil.renderJson(response, Status.SC_UNAUTHORIZED.custStatusMsg("令牌已过期请重新登录"), null);
        };
    }


    /**
     * 认证管理器，登录时会传参给它
     * 无需使用它，因为我们自定义了WxAuthenticationManager
     *
     * @return
     * @throws Exception
     */
//    @Bean
//    public AuthenticationManager authenticationManager() throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }


    /**
     * 放行所有不需要登录就可以访问的请求，参见 AuthController 也可以在 configure(HttpSecurity)
     * 中配置 http.authorizeRequests().antMatchers("/api/auth/**").permitAll()
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers("/ignore1", "/ignore2", "/user/register");
    }

}
