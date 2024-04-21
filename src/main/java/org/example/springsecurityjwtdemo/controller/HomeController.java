package org.example.springsecurityjwtdemo.controller;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.domain.User;
import org.example.springsecurityjwtdemo.jwt.JwtUtil;
import org.example.springsecurityjwtdemo.repository.MemoryTokenRepository;
import org.example.springsecurityjwtdemo.repository.MemoryUserRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final MemoryUserRepository userRepository;
    private final MemoryTokenRepository tokenRepository;
    private final JwtUtil jwtUtil;

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/any")
    public String any() {
        return "any";
    }

    @GetMapping("/join")
    public User joinProcess(String username, String password) {
        return userRepository.save(username, password);
    }

    @GetMapping("/accessToken")
    public String accessToken(String refreshToken){

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);
        List<String> tokens = tokenRepository.find(username)
                .orElseThrow(() -> new RuntimeException("token not found"));

        if (tokens.contains(refreshToken) == false || jwtUtil.isExpired(refreshToken)) {
            return "refresh token expired";
        }

        return "Bearer " + jwtUtil.createToken(username, role, jwtUtil.accessTokenExpireMs);
    }
}
