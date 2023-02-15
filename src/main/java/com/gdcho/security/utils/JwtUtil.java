package com.gdcho.security.utils;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;
import com.gdcho.security.common.Consts;
import com.gdcho.security.common.Status;
import com.gdcho.security.config.JwtConfig;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.exception.SecurityException;
import com.gdcho.security.security.WxAuthenticationToken;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

@EnableConfigurationProperties(JwtConfig.class)
@Component
@Slf4j
public class JwtUtil {
    @Autowired
    private JwtConfig jwtConfig;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Autowired
    SecretKey signatureKey;

    /**
     * 创建JWT，并将JWT以，前缀:userId : JWT的形式存储到redis
     *
     * @param id      用户id
     * @param subject 用户名
     * @return JWT
     */
    @Deprecated
    public String createJWT(Long id,
                            String subject,
                            String openId,
                            String sessionKey,
                            Collection<? extends GrantedAuthority> authorities) {
        Date now = new Date();
        JwtBuilder builder = Jwts.builder()
                                 .setId(id.toString())
                                 .setSubject(subject)
                                 .setIssuedAt(now)
                                 .claim(Consts.JWT_OPENID, openId)
                                 .claim(Consts.JWT_SESSION_KEY, sessionKey)
                                 .claim(Consts.JWT_AUTHORITIES, authorities)
                                 .signWith(signatureKey);

        // 设置过期时间
        Long ttl = jwtConfig.getTtl();
        if (ttl > 0) {
            builder.setExpiration(DateUtil.offsetMillisecond(now,
                                                             ttl.intValue()));
        }

        String jwt = builder.compact();
        // 将生成的JWT保存至Redis
        stringRedisTemplate.opsForValue()
                           .set(Consts.REDIS_JWT_PREFIX + id,
                                jwt,
                                ttl,
                                TimeUnit.MILLISECONDS);
        return jwt;
    }

    /**
     * 通过Authentication，创建JWT
     *
     * @param authentication 用户认证信息
     * @return JWT
     */
    @Deprecated
    public String createJWT(Authentication authentication) {
        WxAuthenticationToken wxAuthenticationToken = (WxAuthenticationToken) authentication;
        UserPrincipal users = wxAuthenticationToken.getUserPrincipal();
        return createJWT(
                users.getId(),
                users.getUsername(),
                users.getOpenId(),
                users.getSessionKey(),
                wxAuthenticationToken.getAuthorities());
    }

    /**
     * 传递Claims创建JWT
     * @param claims claims最终会映射为JSON数据
     * @return JWT
     */
    public String createJWT(Map<String, Object> claims) {
        return Jwts.builder().setClaims(claims).signWith(signatureKey).compact();
    }

    public Claims parseJWTtoClaims(String jwt) {
        try {
            return Jwts.parserBuilder().setSigningKey(signatureKey).build().parseClaimsJws(jwt).getBody();
        } catch (UnsupportedJwtException e) {
            log.error("不支持的 Token");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (MalformedJwtException e) {
            log.error("Token 无效");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (SignatureException e) {
            log.error("无效的 Token 签名");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (IllegalArgumentException e) {
            log.error("Token 参数不存在");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        }
    }


    /**
     * 生成jwt签名
     * 因为JWT生成、解析的签名要前后一致
     *
     * @return 签名
     */
    public String generateSignature() {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Encoders.BASE64.encode(secretKey.getEncoded());
    }


    /**
     * 测试JWT生成，输出JWT与Base64签名
     * @param id 用户id
     * @param subject 用户姓名
     */
    public void testCreateJWT(Long id,
                              String subject) {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String encode = Encoders.BASE64.encode(secretKey.getEncoded());
        Date now = new Date();
        JwtBuilder builder = Jwts.builder()
                                 .setId(id.toString())
                                 .setSubject(subject)
                                 .setIssuedAt(now)
                                 .signWith(secretKey);

        long ttl = 1000L * 60 * 60 * 24 * 7;
        builder.setExpiration(DateUtil.offsetMillisecond(now, (int) ttl));
        Map<String, String> map = new HashMap<>(2);
        System.out.println("JWT = " + builder.compact());
        System.out.println("encode = " + encode);

    }


    /**
     * 测试解析JWT，通过签名解析JWT
     * @param jwt JWT
     * @param keys Base64签名
     * @return JWT解析后储存的实体
     */
    public Claims testParseJWT(String jwt,
                               String keys) {
        byte[] decode = Decoders.BASE64.decode(keys);
        SecretKey secretKey = Keys.hmacShaKeyFor(decode);
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(jwt).getBody();
    }

    /**
     * 解析JWT
     *
     * @param jwt JWT
     * @return {@link Claims}
     */
    public Claims parseJWT(String jwt) throws RuntimeException {
        try {

            Claims claims = Jwts.parserBuilder().setSigningKey(signatureKey).build().parseClaimsJws(jwt).getBody();

            String id = claims.getId();
            String redisKey = Consts.REDIS_JWT_PREFIX + id;

            // 校验redis中的JWT是否存在
            Long expire = stringRedisTemplate.getExpire(redisKey, TimeUnit.MILLISECONDS);
            if (Objects.isNull(expire) || expire <= 0) {
                throw new SecurityException(Status.TOKEN_EXPIRED);
            }

            // 校验redis中的JWT是否与当前的一致，不一致则代表用户已注销/用户在不同设备登录，均代表JWT已过期
            String redisToken = stringRedisTemplate.opsForValue().get(redisKey);
            if (!StrUtil.equals(jwt, redisToken)) {
                throw new SecurityException(Status.TOKEN_OUT_OF_CTRL);
            }
            return claims;
        } catch (ExpiredJwtException e) {
            log.error("Token 已过期");
            throw new SecurityException(Status.TOKEN_EXPIRED);
        } catch (UnsupportedJwtException e) {
            log.error("不支持的 Token");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (MalformedJwtException e) {
            log.error("Token 无效");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (SignatureException e) {
            log.error("无效的 Token 签名");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        } catch (IllegalArgumentException e) {
            log.error("Token 参数不存在");
            throw new SecurityException(Status.TOKEN_PARSE_ERROR);
        }
    }

    /**
     * 设置JWT过期
     *
     * @param request 请求
     */
    public void invalidateJWT(HttpServletRequest request) throws RuntimeException {
        String jwt = getJwtFromRequest(request);
        String id = getIdFromJWT(jwt);
        // 从redis中清除JWT
        stringRedisTemplate.delete(Consts.REDIS_JWT_PREFIX + id);
    }

    /**
     * 根据 jwt 获取用户名
     *
     * @param jwt JWT
     * @return 用户名
     */
    public String getUsernameFromJWT(String jwt) throws RuntimeException {
        Claims claims = parseJWT(jwt);
        return claims.getSubject();
    }

    /**
     * 根据 jwt 获取用户ID
     *
     * @param jwt JWT
     * @return ID
     */
    public String getIdFromJWT(String jwt) throws RuntimeException {
        Claims claims = parseJWT(jwt);
        return claims.getId();
    }

    /**
     * 从 request 的 header 中获取 JWT
     *
     * @param request 请求
     * @return JWT
     */
    public String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(Consts.AUTHORIZATION_HEADER);
        if (StrUtil.isNotBlank(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
