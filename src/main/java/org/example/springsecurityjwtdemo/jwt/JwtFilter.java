package org.example.springsecurityjwtdemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.domain.User;
import org.example.springsecurityjwtdemo.service.CustomUserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

            String authorizationHeader = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if (authorizationHeader == null || authorizationHeader.startsWith("Bearer ") == false) {
            System.out.println("token null");
            filterChain.doFilter(request, response);
            return;
        }
        // 토큰만료 검증
        String token = authorizationHeader.split(" ")[1];
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);
        User user = new User(username, null, role);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        // 토큰인가확인 및 인증처리
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        if (authentication.isAuthenticated() == false) {
            System.out.println("authentication is not valid");
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
