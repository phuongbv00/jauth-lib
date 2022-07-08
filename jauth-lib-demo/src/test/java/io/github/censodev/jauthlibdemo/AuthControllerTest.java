package io.github.censodev.jauthlibdemo;

import io.github.censodev.jauthlibcore.TokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.*;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerTest {
    @LocalServerPort
    int port;

    String baseURI;

    @Autowired
    TestRestTemplate restTemplate;

    @Autowired
    TokenProvider tokenProvider;

    @Autowired
    UserRepository userRepository;

    @BeforeEach
    void setUp() {
        baseURI = "http://localhost:" + port;
    }

    @Test
    void hello_NoToken_401() {
        ResponseEntity<String> res = restTemplate.getForEntity(baseURI + "/api/auth/hello", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, res.getStatusCode());
    }

    @Test
    void hello_InvalidToken_401() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "invalid_token");
        HttpEntity request = new HttpEntity(headers);

        ResponseEntity<String> res = restTemplate.exchange(baseURI + "/api/auth/hello", HttpMethod.GET, request, String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, res.getStatusCode());
    }

    @Test
    void hello_ValidToken_200() {
        User user = userRepository.findByUsername("user")
                .orElse(null);
        String token = tokenProvider.generateAccessToken(user);

        HttpHeaders headers = new HttpHeaders();
        headers.add(tokenProvider.getHeader(), tokenProvider.getPrefix() + token);
        HttpEntity request = new HttpEntity(headers);

        ResponseEntity<String> res = restTemplate.exchange(baseURI + "/api/auth/hello", HttpMethod.GET, request, String.class);
        assertEquals(HttpStatus.OK, res.getStatusCode());
    }

    @Test
    void login_ValidCred_200() {
        Map<String, String> params = new HashMap<String, String>() {{
            put("usn", "user");
            put("pwd", "user");
        }};
        ResponseEntity<String> res = restTemplate.getForEntity(baseURI + "/api/auth/login?usn={usn}&pwd={pwd}", String.class, params);
        assertEquals(HttpStatus.OK, res.getStatusCode());
    }

    @Test
    void login_InvalidCred_401() {
    }
}