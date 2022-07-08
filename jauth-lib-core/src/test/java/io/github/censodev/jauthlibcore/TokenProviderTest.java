package io.github.censodev.jauthlibcore;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class TokenProviderTest {
    static final String SECRET = "1234567890qwertyuiopasdfghjklzxcvbnm!@#$&*()";
    TokenProvider tokenProvider;
    CanAuth user;

    @BeforeEach
    void setUp() {
        tokenProvider = TokenProvider.builder()
                .secret(SECRET)
                .build();
        user = new UserTest(Arrays.asList("ROLE_ADMIN", "ROLE_CUSTOMER"), "admin");
    }

    @Test
    void generateAccessToken() {
        assertDoesNotThrow(() -> tokenProvider.generateAccessToken(user));
    }

    @Test
    void generateRefreshToken() {
        assertDoesNotThrow(() -> tokenProvider.generateRefreshToken(user));
    }

    @Test
    void getCredentials() {
        String token = tokenProvider.generateAccessToken(user);
        assertDoesNotThrow(() -> tokenProvider.getCredential(token, UserTest.class));
    }

    @Test
    void validateTokenHappyCase() {
        String token = tokenProvider.generateAccessToken(user);
        assertDoesNotThrow(() -> tokenProvider.validateToken(token));
    }

    @Test
    void validateTokenExpectWeakKeyException() {
        String token = tokenProvider.generateAccessToken(user);
        tokenProvider = tokenProvider.toBuilder()
                .secret("1234567890")
                .build();
        assertThrows(WeakKeyException.class, () -> tokenProvider.validateToken(token));
    }

    @Test
    void validateTokenExpectMalformedJwtException() {
        String token = "1234567890";
        assertThrows(MalformedJwtException.class, () -> tokenProvider.validateToken(token));
    }

    @Test
    void validateTokenExpectExpiredJwtException() {
        tokenProvider = tokenProvider.toBuilder()
                .expireInMillisecond(1)
                .build();
        String token = tokenProvider.generateAccessToken(user);
        assertThrows(ExpiredJwtException.class, () -> tokenProvider.validateToken(token));
    }

    @Test
    void getHeader() {
        assertEquals("Authorization", tokenProvider.getHeader());
    }

    @Test
    void getPrefix() {
        assertEquals("Bearer ", tokenProvider.getPrefix());
    }

    @Test
    void getExpiration() {
        assertEquals(3_600_000, tokenProvider.getExpireInMillisecond());
    }

    @Test
    void getSecret() {
        assertEquals(SECRET, tokenProvider.getSecret());
    }

    @Test
    void getRefreshTokenExpireInMillisecond() {
        assertEquals(86_400_000, tokenProvider.getRefreshTokenExpireInMillisecond());
    }

    @Test
    void getCredentialClaimKey() {
        assertEquals("credential", tokenProvider.getCredentialClaimKey());
    }

    @Test
    void getSignatureAlgorithm() {
        assertEquals(SignatureAlgorithm.HS256, tokenProvider.getSignatureAlgorithm());
    }

    @Test
    void getPrinciple() {
        String token = tokenProvider.generateAccessToken(user);
        assertEquals(user.principle(), tokenProvider.getPrinciple(token));
    }
}
