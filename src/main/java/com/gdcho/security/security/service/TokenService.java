package com.gdcho.security.security.service;


import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import com.gdcho.security.common.Consts;
import com.gdcho.security.config.JwtConfig;
import com.gdcho.security.entity.vo.UserPrincipal;
import com.gdcho.security.utils.JwtUtil;
import com.gdcho.security.utils.RedisUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@EnableConfigurationProperties(JwtConfig.class)
@Service
public class TokenService {

    @Autowired
    private RedisUtil redisUtil;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtConfig jwtConfig;

    public Long SIXTY_MINUTE = 60L * 60 * 60;

    /**
     * 获取用户主体信息。
     * 解析JWT，得到userId -> REDIS_USER_KEY + userid 找到Redis的用户数据 -> 返回数据
     *
     * @param request 请求
     * @return 用户主体数据
     */
    public UserPrincipal getUserPrincipal(HttpServletRequest request) {
        String jwt = jwtUtil.getJwtFromRequest(request);
        if (StrUtil.isNotEmpty(jwt)) {
            Claims claims = parseJwt(jwt);
            Long userId = claims.get(Consts.JWT_CLAIM_KEY, Long.class);

            String REDIS_USER_KEY = getUserRedisToken(userId);
            return redisUtil.getCacheObject(REDIS_USER_KEY);
        }
        return null;
    }

    public void setUserPrincipal(UserPrincipal userPrincipal) {
        if (ObjUtil.isNotNull(userPrincipal) && ObjUtil.isNotNull(userPrincipal.getId())) {
            String REDIS_USER_KEY = getUserRedisToken(userPrincipal.getId());
            redisUtil.setCacheObject(REDIS_USER_KEY, userPrincipal, jwtConfig.getTtl(), TimeUnit.MILLISECONDS);
        }
    }


    /**
     * 删除用户在redis中的数据
     *
     * @param userId 用户id
     */
    public void invalidateToken(Long userId) {
        String REDIS_USER_KEY = getUserRedisToken(userId);
        redisUtil.deleteObject(REDIS_USER_KEY);
    }

    /**
     * 验证令牌有效性，时常如果小于60分钟，则刷新Redis令牌过期时间
     *
     * @param userPrincipal 用户主体
     */
    public void verifyTokenExpire(UserPrincipal userPrincipal) {
        Long expireTime = userPrincipal.getExpireTime() == null ? 0 : userPrincipal.getExpireTime();
        long currentTime = System.currentTimeMillis();
        if (expireTime - currentTime < SIXTY_MINUTE) {
            refreshRedisToken(userPrincipal);
        }
    }

    /**
     * 刷新redis中当前token的过期时间
     *
     * @param userPrincipal 用户主体
     */
    public void refreshRedisToken(UserPrincipal userPrincipal) {
        userPrincipal.setLastLoginTime(new Date());
        String REDIS_USER_KEY = getUserRedisToken(userPrincipal.getId());
        userPrincipal.setExpireTime(userPrincipal.getLastLoginTime().getTime() + jwtConfig.getTtl());
//        redisCache.put(REDIS_USER_KEY, userPrincipal);
        redisUtil.setCacheObject(REDIS_USER_KEY, userPrincipal, jwtConfig.getTtl(), TimeUnit.MILLISECONDS);
    }


    /**
     * 创建jwt令牌
     *
     * @param userPrincipal 用户主体
     * @return jwt令牌
     */
    public String createJwt(UserPrincipal userPrincipal) {
        Map<String, Object> claims = new HashMap<>();

        refreshRedisToken(userPrincipal);
        // 添加生成JWT的随机性UUID，因为每次创建JWT时签名是一样的，JWT只存储了userId，每次生成的JWT都是一样的。
        String uuid = UUID.randomUUID().toString();
        claims.put("uuid", uuid);

        claims.put(Consts.JWT_CLAIM_KEY, userPrincipal.getId());

        return jwtUtil.createJWT(claims);
    }

    /**
     * 解析jwt
     *
     * @param jwt
     * @return
     */
    public Claims parseJwt(String jwt) {
        return jwtUtil.parseJWTtoClaims(jwt);
    }

    /**
     * 得到用户存储在redis上的key：REDIS_USER_PREFIX + userId
     *
     * @param userId
     * @return
     */
    public String getUserRedisToken(Long userId) {
        return Consts.REDIS_USER_PREFIX + userId;
    }

}
