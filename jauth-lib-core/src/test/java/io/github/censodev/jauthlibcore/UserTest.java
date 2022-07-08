package io.github.censodev.jauthlibcore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UserTest implements CanAuth {
    private List<String> authorities = Collections.emptyList();
    private String username;
    private Instant createdAt;

    public UserTest(List<String> authorities, String username) {
        this.authorities = authorities;
        this.username = username;
        createdAt = Instant.now();
    }

    public UserTest() {
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public String principle() {
        return username;
    }

    @Override
    public List<String> authorities() {
        return new ArrayList<>(authorities);
    }
}
