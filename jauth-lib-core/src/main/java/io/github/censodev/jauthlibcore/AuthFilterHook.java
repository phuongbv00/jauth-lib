package io.github.censodev.jauthlibcore;

public interface AuthFilterHook {
    void beforeVerify(TokenProvider tokenProvider, String token);

    void onPassed(Credential credential);

    void onFailed(Exception ex);
}
