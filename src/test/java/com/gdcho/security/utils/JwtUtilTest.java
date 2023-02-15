package com.gdcho.security.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Arrays;

class JwtUtilTest {
    JwtUtil jwtUtil = new JwtUtil();

    @Test
    void createJWT() {
        jwtUtil.testCreateJWT(123465L, "abc");
    }

    @Test
    void parseJWT() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NjUiLCJzdWIiOiJhYmMiLCJpYXQiOjE2NzYwNDE5MTQsImV4cCI6MTY3NjY0NjcxNH0.3qg2xkXOhoD5ArSfP_VBJCSC9b1yGaqk-UAMi8yk6i8";
        String key = "PiChTGN3oZJI+F9jZkFlIvHV1bQAgavOCchIWAiDDrY=";
        Claims claims = jwtUtil.testParseJWT(jwt, key);
        System.out.println("claims.toString() = " + claims.toString());
    }

    @Test
    void generatorKeys() {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        System.out.println("secretKey = " + Arrays.toString(secretKey.getEncoded()));

        System.out.println(Encoders.BASE64.encode(secretKey.getEncoded()));
    }

    @Test
    void getKeys() {
        System.out.println("jwtUtil.generateSignature = " + jwtUtil.generateSignature());
    }
}