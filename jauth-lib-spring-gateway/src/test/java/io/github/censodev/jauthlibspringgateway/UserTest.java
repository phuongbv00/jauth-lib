package io.github.censodev.jauthlibspringgateway;

import io.github.censodev.jauthlibcore.Credential;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UserTest implements Credential {
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
    public String getSubject() {
        return username;
    }

    @Override
    public String getPrinciple() {
        return username;
    }

    @Override
    public List<String> getAuthorities() {
        return new ArrayList<>(authorities);
    }
}
