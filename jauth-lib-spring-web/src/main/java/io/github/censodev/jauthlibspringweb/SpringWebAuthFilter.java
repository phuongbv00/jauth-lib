package io.github.censodev.jauthlibspringweb;

import io.github.censodev.jauthlibcore.AuthFilterHook;
import io.github.censodev.jauthlibcore.Credential;
import io.github.censodev.jauthlibcore.TokenProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class SpringWebAuthFilter<T extends Credential> implements Filter {
    private final TokenProvider tokenProvider;
    private final Class<T> credentialClass;
    private final AuthFilterHook hook;

    public SpringWebAuthFilter(TokenProvider tokenProvider, Class<T> credentialClass) {
        this.tokenProvider = tokenProvider;
        this.credentialClass = credentialClass;
        this.hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(Credential credential) {

            }

            @Override
            public void onFailed(Exception ex) {

            }
        };
    }

    public SpringWebAuthFilter(TokenProvider tokenProvider, Class<T> credentialClass, AuthFilterHook hook) {
        this.tokenProvider = tokenProvider;
        this.credentialClass = credentialClass;
        this.hook = hook;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = ((HttpServletRequest) request).getHeader(tokenProvider.getHeader());

        if (header == null || !header.startsWith(tokenProvider.getPrefix())) {
            hook.onFailed(new Exception("Invalid HTTP header for authentication"));
            chain.doFilter(request, response);
            return;
        }

        String token = header.replace(tokenProvider.getPrefix(), "");
        try {
            hook.beforeVerify(tokenProvider, token);
            tokenProvider.validateToken(token);
            T credential = tokenProvider.getCredential(token, credentialClass);
            List<SimpleGrantedAuthority> authorities = credential
                    .getAuthorities()
                    .stream().map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            String username = credential.getUsername();
            Authentication auth = new UsernamePasswordAuthenticationToken(username, credential, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            hook.onPassed(credential);
        } catch (Exception e) {
            hook.onFailed(e);
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}