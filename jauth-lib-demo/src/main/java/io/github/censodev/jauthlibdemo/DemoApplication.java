package io.github.censodev.jauthlibdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;
import java.util.Arrays;

@SpringBootApplication
public class DemoApplication {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @PostConstruct
    void postConstruct() {
        userRepository.save(User.builder()
                .username("user")
                .password(passwordEncoder.encode("user"))
                .roles(Arrays.asList(User.RoleEnum.ROLE_ADMIN, User.RoleEnum.ROLE_MODERATOR))
                .build());
    }
}
