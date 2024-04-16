package org.example.springsecurityjwtdemo.repository;


import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.domain.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class MemoryUserRepository {
    private static Map<String, User> users = new HashMap<>();
    private final PasswordEncoder passwordEncoder;

    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public User save(String username, String password) {
        users.put(username, new User(username, passwordEncoder.encode(password), "ROLE_ADMIN"));
        return users.get(username);
    }
}
