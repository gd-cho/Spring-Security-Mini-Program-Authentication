package com.gdcho.security.config;

import cn.hutool.core.lang.Snowflake;
import cn.hutool.core.util.IdUtil;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.util.Arrays;

@Configuration
@AutoConfigureAfter(RedisAutoConfiguration.class)
@EnableConfigurationProperties(JwtConfig.class)
@EnableCaching
public class CustomConfig {

    @Autowired
    JwtConfig jwtConfig;

    @Bean
    public Snowflake snowflake() {
        return IdUtil.getSnowflake(1,
                                   1);
    }

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();

        mappingJackson2HttpMessageConverter.setSupportedMediaTypes(
                Arrays.asList(MediaType.TEXT_HTML, MediaType.TEXT_PLAIN));

        restTemplate.getMessageConverters().add(mappingJackson2HttpMessageConverter);

        return restTemplate;
    }

    /**
     * 默认情况下的模板只能支持RedisTemplate<String, String>，也就是只能存入字符串，因此支持序列化
     */
    @Bean
    public RedisTemplate<String, Serializable> redisCacheTemplate(LettuceConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Serializable> template = new RedisTemplate<>();

//        Jackson2JsonRedisSerializer<Object> jsonRedisSerializer = new Jackson2JsonRedisSerializer<>(new ObjectMapper(),
//                                                                                                    Object.class);
//
//        RedisSerializer stringSerializer = new StringRedisSerializer(StandardCharsets.UTF_8);
//        template.setKeySerializer(stringSerializer);
//        template.setValueSerializer(stringSerializer);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setConnectionFactory(redisConnectionFactory);
        return template;
    }

    @Bean(name = "signatureKey")
    public SecretKey parseSignature() {
        String signature = jwtConfig.getSignature();
        byte[] decode = Decoders.BASE64.decode(signature);
        return Keys.hmacShaKeyFor(decode);
    }

    /**
     * 加密方式
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
