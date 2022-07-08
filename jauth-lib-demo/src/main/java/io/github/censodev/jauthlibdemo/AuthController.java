package io.github.censodev.jauthlibdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
public class AuthController {
    @Autowired
    AuthService authService;

    @GetMapping("hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("login")
    public AuthService.Tokens login(@RequestParam String usn,
                        @RequestParam String pwd) {
        return authService.login(usn, pwd);
    }
}
