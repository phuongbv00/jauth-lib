package io.github.censodev.jauthlibspringweb;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.censodev.jauthlibcore.AuthFilterHook;
import io.github.censodev.jauthlibcore.CanAuth;
import io.github.censodev.jauthlibcore.TokenProvider;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SpringWebAuthFilterTest {
    static final String SECRET = "1234567890qwertyuiopasdfghjklzxcvbnm!@#$&*()";
    SpringWebAuthFilter<UserTest> filter;
    TokenProvider tokenProvider;
    AuthFilterHook hook;
    MockHttpServletRequest req;
    MockHttpServletResponse res;
    MockFilterChain chain;

    @BeforeEach
    void setUp() {
        tokenProvider = TokenProvider.builder()
                .secret(SECRET)
                .build();
        req = new MockHttpServletRequest();
        res = new MockHttpServletResponse();
        chain = new MockFilterChain();
        SecurityContextHolder.clearContext();
    }

    @Test
    void expect401MissingAuthHeader() throws ServletException, IOException {
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
        filter = new SpringWebAuthFilter<>(tokenProvider, UserTest.class, hook);
        filter.doFilter(req, res, chain);
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
        filter = new SpringWebAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(headerValues).forEach(val -> {
            req.addHeader(tokenProvider.getHeader(), val);
            chain = new MockFilterChain();
            assertDoesNotThrow(() -> filter.doFilter(req, res, chain));
        });
    }

    @Test
    void expect401InvalidToken() throws JsonProcessingException {
        String[] tokens = new String[]{
                "1234567890",
                tokenProvider.toBuilder().secret("1234567890").build().generateAccessToken(new UserTest()),
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
        filter = new SpringWebAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(tokens).forEach(token -> {
            req.addHeader(tokenProvider.getHeader(), tokenProvider.getPrefix() + token);
            chain = new MockFilterChain();
            assertDoesNotThrow(() -> filter.doFilter(req, res, chain));
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
        filter = new SpringWebAuthFilter<>(tokenProvider, UserTest.class, hook);
        Arrays.stream(tokens).forEach(token -> {
            req.addHeader(tokenProvider.getHeader(), tokenProvider.getPrefix() + token);
            chain = new MockFilterChain();
            assertDoesNotThrow(() -> filter.doFilter(req, res, chain));
        });
    }

    @Test
    void expectHookNotNull() throws JsonProcessingException {
        filter = new SpringWebAuthFilter<>(tokenProvider, UserTest.class);
        req.addHeader(tokenProvider.getHeader(), tokenProvider.getPrefix() + tokenProvider.generateAccessToken(new UserTest()));
        chain = new MockFilterChain();
        assertDoesNotThrow(() -> filter.doFilter(req, res, chain));
    }
}