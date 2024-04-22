package org.example.springsecurityjwtdemo.repository;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.jwt.JwtUtil;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
@RequiredArgsConstructor
public class MemoryTokenRepository {

    private static Map<String, List<String>> refreshTokens = new HashMap<>();
    private final JwtUtil jwtUtil;

    public void save(String username, String token) {
        List<String> tokens = refreshTokens.getOrDefault(username, new ArrayList<>());
        tokens.add(token);
        refreshTokens.put(username, tokens);
    }

    public Optional<List<String>> find(String username) {
        return Optional.ofNullable(refreshTokens.get(username));
    }

    public void deleteAllExpired() {
        for (List<String> tokens : refreshTokens.values()) {
            tokens.removeIf(token -> jwtUtil.isExpired(token));
        }
    }
}
