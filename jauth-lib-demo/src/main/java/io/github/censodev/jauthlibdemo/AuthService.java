package io.github.censodev.jauthlibdemo;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

public interface AuthService {
    @Getter
    @Setter
    @Builder
    class Tokens {
        private String accessToken;
        private String refreshToken;
    }

    Tokens login(String usn, String pwd);
}
