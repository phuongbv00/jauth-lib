package io.github.censodev.jauthlibcore;

public interface AuthFilterHook {
    void beforeVerify(TokenProvider tokenProvider, String token);

    void onPassed(CanAuth canAuth);

    void onFailed(Exception ex);
}
