package org.example.springsecurityjwtdemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtdemo.repository.MemoryTokenRepository;
import org.example.springsecurityjwtdemo.service.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final MemoryTokenRepository tokenRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String userName = obtainUsername(request);
        String password = obtainPassword(request);
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userName, password);
        return authenticationManager.authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = customUserDetails.getUsername();
        GrantedAuthority authority = null;
        for (GrantedAuthority localAuthority : authResult.getAuthorities()) {
            authority = localAuthority;
        }
        String role = authority.getAuthority();

        //액세스토큰 설정
        String accessToken = jwtUtil.createToken(username, role, jwtUtil.accessTokenExpireMs);
        response.addHeader("Authorization", "Bearer " + accessToken);

        //리프레쉬 토큰 설정
        String refreshToken = jwtUtil.createToken(username, role, jwtUtil.refreshTokenExpireMs);
        response.addHeader("X-Refresh-Token", refreshToken);
        tokenRepository.save(customUserDetails.getUser().getUsername(), refreshToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);

    }
}
