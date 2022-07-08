package io.github.censodev.jauthlibdemo;

import io.github.censodev.jauthlibcore.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    TokenProvider tokenProvider;

    @Override
    public Tokens login(String usn, String pwd) {
        return userRepository.findByUsername(usn)
                .filter(u -> passwordEncoder.matches(pwd, u.getPassword()))
                .map(u -> Tokens.builder()
                        .accessToken(tokenProvider.generateAccessToken(u))
                        .refreshToken(tokenProvider.generateRefreshToken(u))
                        .build())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }
}
