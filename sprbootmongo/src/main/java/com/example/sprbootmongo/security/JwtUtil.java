package com.example.sprbootmongo.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY = "your_secret_key_which_must_be_at_least_32_chars";
    private static final long ACCESS_TOKEN_EXPIRATION = 15 * 60 * 1000; // 20 giây (đổi lại theo yêu cầu ban đầu)
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 ngày

    private static final SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(key)
                .compact();
    }

    public static String generateRefreshToken(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(key)
                .compact();
    }

    public static String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(key) // Kiểm tra chữ ký
                .build()
                .parseSignedClaims(token) // Dùng parseSignedClaims thay vì parseUnsecuredClaims
                .getPayload()
                .getSubject();
    }

    public static String extractRole(String token) {
        return Jwts.parser()
                .verifyWith(key) // Kiểm tra chữ ký
                .build()
                .parseSignedClaims(token) // Dùng parseSignedClaims thay vì parseUnsecuredClaims
                .getPayload()
                .get("role", String.class);
    }
}