package com.workshop.bouali.config;

import com.workshop.bouali.dao.UserDao;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);
        final String userEmail;
        final String jwtToken;

        // 1. 헤더에서 JWT 토큰 추출
        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwtToken = authHeader.substring(7);

        // 2. JWT에서 사용자 이메일 추출
        userEmail = jwtUtils.extractUsername(jwtToken);

        // 3. 사용자 인증 처리
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDao.findUserByEmail(userEmail);

            // 5. 토큰이 유효한 경우, SecurityContextHolder에 사용자 정보 설정
            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                // 5.1 유효한 토큰인 경우, 사용자 정보 가져오기
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // 5.2 토큰에 추가적인 정보 설정
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 5.3 SecurityContextHolder에 사용자 정보 설정
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 6. 다음 필터로 전달
        filterChain.doFilter(request, response);
    }
}
