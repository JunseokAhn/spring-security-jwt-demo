package org.example.springsecurityjwtdemo.repository;

import org.example.springsecurityjwtdemo.domain.User;
import org.springframework.stereotype.Repository;

import java.util.*;

@Repository
public class MemoryTokenRepository {

    private static Map<String, List<String>> refreshTokens = new HashMap<>();

    public void save(String username, String token) {
        List<String> tokens = refreshTokens.getOrDefault(username, new ArrayList<>());
        tokens.add(token);
        refreshTokens.put(username, tokens);
    }
    public Optional<List<String>> find(String username) {
        return Optional.ofNullable(refreshTokens.get(username));
    }

}
