package io.github.censodev.jauthlibspringgateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.censodev.jauthlibcore.AuthFilterHook;
import io.github.censodev.jauthlibcore.CanAuth;
import io.github.censodev.jauthlibcore.TokenProvider;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class SpringGatewayAuthFilterTest {
    static final String SECRET = "1234567890qwertyuiopasdfghjklzxcvbnm!@#$&*()";
    SpringGatewayAuthFilter<UserTest> filter;
    TokenProvider tokenProvider;
    AuthFilterHook hook;
    MockServerWebExchange exchange;
    GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        tokenProvider = TokenProvider.builder()
                .secret(SECRET)
                .build();
        chain = mock(GatewayFilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @Test
    void expect401MissingAuthHeader() {
        hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(CanAuth canAuth) {
                assertNull(canAuth);
            }

            @Override
            public void onFailed(Exception ex) {
                assertNull(SecurityContextHolder.getContext().getAuthentication());
                assertNotNull(ex);
                assertEquals("Invalid HTTP header for authentication", ex.getMessage());
            }
        };
        filter = new SpringGatewayAuthFilter<>(tokenProvider, UserTest.class, hook);
        exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/test")
                .build());
        filter.filter(exchange, chain);
    }

    @Test
    void expect401InvalidAuthHeaderValue() throws JsonProcessingException {
        String[] headerValues = new String[]{"", "aaa", tokenProvider.generateAccessToken(new UserTest())};
        hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(CanAuth canAuth) {
                assertNull(canAuth);
            }

            @Override
            public void onFailed(Exception ex) {
                assertNull(SecurityContextHolder.getContext().getAuthentication());
                assertNotNull(ex);
                assertEquals("Invalid HTTP header for authentication", ex.getMessage());
            }
        };
        filter = new SpringGatewayAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(headerValues).forEach(val -> {
            exchange = MockServerWebExchange.from(MockServerHttpRequest
                    .get("/test")
                    .header(tokenProvider.getHeader(), val)
                    .build());
            filter.filter(exchange, chain);
        });
    }

    @Test
    void expect401InvalidToken() throws JsonProcessingException {
        String[] tokens = new String[]{
                "1234567890",
                tokenProvider.toBuilder().secret("1234567890123456789012345678901234567890").build().generateAccessToken(new UserTest()),
                tokenProvider.toBuilder().expireInMillisecond(1).build().generateAccessToken(new UserTest()),
        };
        hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(CanAuth canAuth) {
                assertNull(canAuth);
            }

            @Override
            public void onFailed(Exception ex) {
                assertNull(SecurityContextHolder.getContext().getAuthentication());
                assertNotNull(ex);
                assertInstanceOf(JwtException.class, ex);
            }
        };
        filter = new SpringGatewayAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(tokens).forEach(token -> {
            exchange = MockServerWebExchange.from(MockServerHttpRequest
                    .get("/test")
                    .header(tokenProvider.getHeader(), tokenProvider.getPrefix() + token)
                    .build());
            filter.filter(exchange, chain);
        });
    }

    @Test
    void expect200ValidToken() throws JsonProcessingException {
        String[] tokens = new String[]{
                tokenProvider.generateAccessToken(new UserTest()),
        };
        hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(CanAuth canAuth) {
                assertNotNull(canAuth);
                assertNotNull(SecurityContextHolder.getContext().getAuthentication());
                assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
            }

            @Override
            public void onFailed(Exception ex) {
                assertNull(ex);
            }
        };
        filter = new SpringGatewayAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(tokens).forEach(token -> {
            exchange = MockServerWebExchange.from(MockServerHttpRequest
                    .get("/test")
                    .header(tokenProvider.getHeader(), tokenProvider.getPrefix() + token)
                    .build());
            filter.filter(exchange, chain);
        });
    }

    @Test
    void expectHookNotNull() throws JsonProcessingException {
        filter = new SpringGatewayAuthFilter<>(tokenProvider, UserTest.class);
        exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/test")
                .header(tokenProvider.getHeader(), tokenProvider.getPrefix() + tokenProvider.generateAccessToken(new UserTest()))
                .build());
        assertDoesNotThrow(() -> filter.filter(exchange, chain));
    }
}