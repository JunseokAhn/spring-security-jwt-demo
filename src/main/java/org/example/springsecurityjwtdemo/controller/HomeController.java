package org.example.springsecurityjwtdemo.controller;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.domain.User;
import org.example.springsecurityjwtdemo.repository.MemoryUserRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final MemoryUserRepository repository;

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/join")
    public User joinProcess(String username, String password) {
        return repository.save(username, password);
    }

}
