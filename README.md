# Spring Boot + Spring Security + 小程序实现登录鉴权

## 技术选型

- Spring Boot：为开发者快捷的使用Spring及相关开发框架。
- Spring Security：基于过滤器链对身份、角色、权限进行校验，自定义过滤器WxJwtAuthenticationFilter进行Token验证、WxAuthenticationFilter对普通登录与微信登录进行区分。
- JWT：对Token进行验证，及从Token中解析有效用户信息判断用户。
- Hutool：提供了一系列常用的用具类。
- Lombok：简化代码编写。

## 认证流程

微信登录：点击登录 - 发送js_code至开发后台 -> 后台过滤器调用微信服务接口相关API - 获得登录认证 -> 登录认证存储至数据库 ->
返回创建的JWT给客户端。

普通登录：输入用户名密码 - 发送至开发后台 -> 后台过滤器获取数据库用户数据 - 密码比对 -> 认证成功 - 返回创建的JWT给客户端。

JWT认证流程：客户端发送JWT至开发后台 -> 后台过滤器解析JWT - 认证成功 -> 返回响应给客户端。

## 一些代码片段

### Security 主要配置 [WebSecurityConfig](src/main/java/com/gdcho/security/config/WebSecurityConfig.java)

```java
public class WebSecurityConfig {
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

        // 关闭csrf
        http.csrf().disable();

        return http.build();
    }
}
```

拒绝访问异常处理

```markdown
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
```

登录失败异常处理

```markdown
@Bean
// 认证异常：登录失败。
public AuthenticationEntryPoint authenticationEntryPoint() {
return (request, response, authException) -> {
System.out.println("【AuthenticationEntryPoint】异常:" + authException.getMessage());
ResponseUtil.renderJson(response, Status.SC_UNAUTHORIZED.custStatusMsg("令牌已过期请重新登录"), null);
};
}
```

### 全局异常拦截 [GlobalExceptionHandler](src/main/java/com/gdcho/security/handler/GlobalExceptionHandler.java)

- 这里只拦截了异常`Exception`，通过instanceof判断它是什么类型的异常。
- 最后有拦截`AccessDeniedException`异常，因为在开启自定义鉴权功能`@EnableMethodSecurity(prePostEnabled = true)`
  ，鉴定权限时不会走Security那套，所以用户无权限访问时，需要捕获异常。

```java

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    @ResponseBody
    public APIResponse<?> handleException(Exception ex) {
        if (ex instanceof BaseException) {
            log.error("【全局异常拦截】BaseException，错误码：{}，错误消息：{}", ((BaseException) ex).getCode(),
                      ex.getMessage());
            return APIResponse.ofException((BaseException) ex);
        } else if (ex instanceof HttpRequestMethodNotSupportedException) {
            log.error("【全局异常拦截】HttpRequestMethodNotSupportedException，当前请求方式：{}，支持请求方式：{}",
                      ((HttpRequestMethodNotSupportedException) ex).getMethod(),
                      JSONUtil.toJsonStr(((HttpRequestMethodNotSupportedException) ex).getSupportedMethods()));
            return APIResponse.ofStatus(Status.HTTP_BAD_METHOD);
        } else if (ex instanceof MethodArgumentNotValidException) {
            log.error("【全局异常拦截】MethodArgumentNotValidException", ex);
            return APIResponse.of(Status.BAD_REQUEST.getCode(),
                                  ((MethodArgumentNotValidException) ex).getBindingResult().getAllErrors().get(0)
                                                                        .getDefaultMessage(), null);
        } else if (ex instanceof ConstraintViolationException) {
            log.error("【全局异常拦截】ConstraintViolationException", ex);
            return APIResponse.of(Status.BAD_REQUEST.getCode(), ((ConstraintViolationException) ex).getConstraintName(),
                                  null);
        } else if (ex instanceof MethodArgumentTypeMismatchException) {
            log.error("【全局异常拦截】MethodArgumentTypeMismatchException: 参数名 {}, 异常信息 {}",
                      ((MethodArgumentTypeMismatchException) ex).getName(), ex.getMessage());
            return APIResponse.ofStatus(Status.PARAM_NOT_MATCH);
        } else if (ex instanceof HttpMessageNotReadableException) {
            log.error("【全局异常拦截】HttpMessageNotReadableException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.PARAM_NOT_NULL);
        } else if (ex instanceof BadCredentialsException) {
            log.error("【全局异常拦截】BadCredentialsException: 错误信息 {}", ex.getMessage());
        } else if (ex instanceof DisabledException) {
            log.error("【全局异常拦截】DisabledException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.USER_DISABLED);
        } else if (ex instanceof NoHandlerFoundException) {
            log.error("【全局异常拦截】NoHandlerFoundException: 错误码 {}, 错误信息 {}",
                      ((NoHandlerFoundException) ex).getStatusCode(), ex.getMessage());
            return APIResponse.ofStatus(Status.REQUEST_NOT_FOUND);
        } else if (ex instanceof AccessDeniedException) {
            log.error("【全局异常拦截】AccessDeniedException: 错误信息 {}", ex.getMessage());
            return APIResponse.ofStatus(Status.SC_ACCESS_DENIED);
        }

        log.error("【全局异常拦截】: 异常信息 {} ", ex.getMessage());
        ex.printStackTrace();
        return APIResponse.ofStatus(Status.OTHER_ERROR.custStatusMsg(ex.getMessage()));
    }
}
```

### 雪花算法生成ID [SnowIdGeneratorConfig](src/main/java/com/gdcho/security/config/SnowIdGeneratorConfig.java)

首先是实现`IdentifierGenerator`自定义ID生成配置

```java
public class SnowIdGeneratorConfig implements IdentifierGenerator {

    @Autowired
    Snowflake snowflake;

    @Override
    public Object generate(SharedSessionContractImplementor session,
                           Object object) throws HibernateException {

        return snowflake.nextId();
    }
}
```

在实体类中使用雪花ID生成算法

```java
public class BaseEntity implements Serializable {
    @Id
    @GeneratedValue(generator = "snowflakeGenerator",
                    strategy = GenerationType.SEQUENCE)
    @GenericGenerator(name = "snowflakeGenerator",
                      strategy = "com.gdcho.security.config.SnowIdGeneratorConfig")
    private Long id;

    // ...
}
```

### 自定义登录过滤器 [WxAuthenticationFilter](src/main/java/com/gdcho/security/security/filter/WxAuthenticationFilter.java)

WxAuthenticationFilter：实现了普通登录与微信登录的处理，具体登录验证逻辑在WxAuthenticationManager。

```java
public class WxAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        log.info("【WxAuthenticationFilter】请求URI为:{}", request.getRequestURI());
        //判断请求是否为POST,禁用GET请求提交数据
        if (!"POST".equals(request.getMethod())) {
//            throw new AuthenticationServiceException("只支持POST请求方式");
            ResponseUtil.renderJson(response,
                                    new SecurityException(Status.HTTP_BAD_METHOD.custStatusMsg("只支持POST请求方式！")));
            return null;
        }

        // 获取微信jsCode与用户名密码
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String jsCode = obtainJsCode(request);

        WxAuthenticationToken unauthenticated;
        UserPrincipal.UserPrincipalBuilder userPrincipalBuilder = UserPrincipal.builder();
        // 普通登录
        if (StrUtil.isNotEmpty(username) && StrUtil.isNotEmpty(password)) {
            userPrincipalBuilder.username(username).password(password);
            unauthenticated = WxAuthenticationToken.unauthenticated(userPrincipalBuilder.build());
            Authentication authenticate = getAuthenticationManager().authenticate(unauthenticated);
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            return authenticate;
        }
        // 微信单点登录
        else if (StrUtil.isNotEmpty(jsCode)) {
            // 发送到微信服务接口认证用户
            WxTokenVO wxToken = wxUtils.getWxToken(jsCode);

            String openid = wxToken.getOpenid();
            String session_key = wxToken.getSession_key();
            Integer errCode = wxToken.getErrcode();
            String errMsg;
            userPrincipalBuilder.openId(openid).sessionKey(session_key);
            if (wxToken.getErrcode() != null && !wxToken.getErrcode().equals(0)) {
                log.info("【WxAuthenticationFilter】微信登录,微信服务接口授权失败,errCode:{},errMsg:{}",
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
                    errMsg = "微信服务接口异常，请查看异常码！";
                }
                // 返回响应
                ResponseUtil.renderJson(response, new SecurityException(errCode, errMsg, null));
                return null;
            }

            unauthenticated = WxAuthenticationToken.unauthenticatedWx(userPrincipalBuilder.build());
            // 验证用户
            Authentication authenticate = getAuthenticationManager().authenticate(unauthenticated);

            SecurityContextHolder.getContext().setAuthentication(authenticate);
            log.info("【WxAuthenticationFilter】请求URI为:{}", request.getRequestURI());
            return authenticate;
        } else {
            ResponseUtil.renderJson(response, Status.USERNAME_NOT_FOUND.custStatusMsg("请输入用户名密码！"), null);
            return null;
        }
    }
}
```

### 自定义登录验证逻辑管理 [WxAuthenticationManager](src/main/java/com/gdcho/security/security/WxAuthenticationManager.java)

`WxAuthenticationManager`直接实现了`AuthenticationManager`，直接绕过了ProviderManager，因为明确了普通登录与微信登录，对登录用户信息进行验证。

```java
public class WxAuthenticationManager implements AuthenticationManager {

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
}

```

### 自定义JWT认证过滤器 [WxJwtAuthenticationFilter](src/main/java/com/gdcho/security/security/filter/WxJwtAuthenticationFilter.java)

```java
public class WxJwtAuthenticationFilter extends OncePerRequestFilter {

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
```

### 权限验证

在[DemoController](src/main/java/com/gdcho/security/controller/DemoController.java) 中`fool1`与`fool2`方法需要权限

```markdown
  @GetMapping("/fool")
@PreAuthorize("@rs.hasPerm('sys:user:view')")
public APIResponse<String> fool() {
return APIResponse.ofSuccess("you are fool!");
}

@GetMapping("/fool2")
@PreAuthorize("@rs.hasPerm('sys:user:query')")
public APIResponse<String> fool2() {
return APIResponse.ofSuccess("you are fool2!");
}
```

而我们自定义了权限验证的方法，在控制器层中用@PreAuthority标注，用户的权限必须满足相应的条件才能得到响应。

而`@rs.hasPerm('sys:user:view')`会访问到一下方法，判定用户是否满足权限。

```java

@Service("rs")
public class RolePermService {

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
}
```

## 待解决问题

- 当用户携带Token访问一个不存在的路径时，判定的响应是AccessDeniedException（无权限访问异常），而不是NoHandlerFoundException（没有处理器异常）。

