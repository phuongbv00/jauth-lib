package io.github.censodev.jauthlibdemo;

import io.github.censodev.jauthlibcore.AuthFilterHook;
import io.github.censodev.jauthlibcore.CanAuth;
import io.github.censodev.jauthlibcore.TokenProvider;
import io.github.censodev.jauthlibspringweb.SpringWebAuthFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Slf4j
public class SecurityConfig {
    @Bean
    public TokenProvider tokenProvider() {
        return TokenProvider.builder()
                .expireInMillisecond(3_600_000)
                .refreshTokenExpireInMillisecond(86_400_000)
                .secret("qwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*()")
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthFilterHook hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {
                log.info("BEFORE VERIFY: token={}", token);
            }

            @Override
            public void onPassed(CanAuth canAuth) {
                log.info("PASSED: credentials={}", canAuth);
            }

            @Override
            public void onFailed(Exception ex) {
                log.info("FAILED: ex={}", ex.getMessage());
            }
        };
        SpringWebAuthFilter<User> filter = new SpringWebAuthFilter<>(tokenProvider(), User.class, hook);
        return http
                .csrf()
                .disable()
                .cors()
                .and()
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .antMatchers("/api/auth/login").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(withDefaults())
                .build();
    }
}
