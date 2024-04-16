package org.example.springsecurityjwtdemo.service;

import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.domain.User;
import org.example.springsecurityjwtdemo.repository.MemoryUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final MemoryUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        System.out.println(user);
        return new CustomUserDetails(user);
    }
}
