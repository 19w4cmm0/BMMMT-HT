package com.example.sprbootmongo.controller;

import com.example.sprbootmongo.model.User;
import com.example.sprbootmongo.repository.UserRepository;
import com.example.sprbootmongo.security.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    private Map<String, Integer> loginAttempts = new HashMap<>();
    private Map<String, Long> lockoutTime = new HashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION = 20 * 1000; // 20 giây

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User user, HttpServletResponse response) {
        String username = user.getUsername();

        // Kiểm tra khóa tài khoản
        if (lockoutTime.containsKey(username) && System.currentTimeMillis() < lockoutTime.get(username)) {
            throw new RuntimeException("Account locked. Try again later.");
        }

        User existingUser = userRepository.findByUsername(username);
        if (existingUser != null && passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
            // Đăng nhập thành công, reset bộ đếm
            loginAttempts.remove(username);
            lockoutTime.remove(username);

            // Tạo accessToken và refreshToken
            String accessToken = JwtUtil.generateToken(username, existingUser.getRole());
            String refreshToken = JwtUtil.generateRefreshToken(username);

            // Lưu refreshToken vào HttpOnly cookie
            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
            refreshTokenCookie.setHttpOnly(true); // Ngăn truy cập qua JavaScript
            refreshTokenCookie.setSecure(true); // Chỉ gửi qua HTTPS
            refreshTokenCookie.setPath("/api/auth/refresh"); // Chỉ áp dụng cho endpoint /api/auth/refresh
            refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 ngày (thời gian sống của refreshToken)
            response.addCookie(refreshTokenCookie);

            // Trả accessToken trong body JSON (giữ nguyên như yêu cầu)
            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            return tokens;
        } else {
            // Đăng nhập thất bại, tăng bộ đếm
            int attempts = loginAttempts.getOrDefault(username, 0) + 1;
            loginAttempts.put(username, attempts);
            if (attempts >= MAX_ATTEMPTS) {
                lockoutTime.put(username, System.currentTimeMillis() + LOCKOUT_DURATION);
                throw new RuntimeException("Too many failed attempts. Account locked for 20 seconds.");
            }
            throw new RuntimeException("Invalid credentials");
        }
    }

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        String username = user.getUsername();
        if (userRepository.findByUsername(username) != null) {
            throw new RuntimeException("Username already exists");
        }
        // Kiểm tra username để ngăn chèn mã JavaScript
        if (!isValidUsername(username)) {
            throw new RuntimeException("Username must be 3-20 characters long and contain only letters, numbers, and underscores");
        }
        if (!isValidPassword(user.getPassword())) {
            throw new RuntimeException("Password must be at least 8 characters, contain uppercase, lowercase, and numbers");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("USER");
        return userRepository.save(user);
    }

    @PostMapping("/refresh")
    public Map<String, String> refreshToken(@CookieValue(name = "refreshToken") String refreshToken) {
        String username = JwtUtil.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username);
        if (user != null) {
            return Map.of("accessToken", JwtUtil.generateToken(username, user.getRole()));
        }
        throw new RuntimeException("Invalid refresh token");
    }

    private boolean isValidUsername(String username) {
        // Username chỉ chứa chữ cái, số, và dấu gạch dưới, dài 3-20 ký tự
        return username != null && username.matches("^[a-zA-Z0-9_]{3,20}$");
    }

    private boolean isValidPassword(String password) {
        return password != null && password.length() >= 8 &&
                password.matches(".*[A-Z].*") && // Có chữ hoa
                password.matches(".*[a-z].*") && // Có chữ thường
                password.matches(".*[0-9].*");   // Có số
    }
}