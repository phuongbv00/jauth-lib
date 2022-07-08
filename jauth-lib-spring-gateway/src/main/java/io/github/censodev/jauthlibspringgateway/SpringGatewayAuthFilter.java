package io.github.censodev.jauthlibspringgateway;

import io.github.censodev.jauthlibcore.AuthFilterHook;
import io.github.censodev.jauthlibcore.CanAuth;
import io.github.censodev.jauthlibcore.TokenProvider;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

public class SpringGatewayAuthFilter<T extends CanAuth> implements GlobalFilter {
    private final TokenProvider tokenProvider;
    private final Class<T> canAuthConcreteClass;
    private final AuthFilterHook hook;

    public SpringGatewayAuthFilter(TokenProvider tokenProvider, Class<T> canAuthConcreteClass) {
        this.tokenProvider = tokenProvider;
        this.canAuthConcreteClass = canAuthConcreteClass;
        this.hook = new AuthFilterHook() {
            @Override
            public void beforeVerify(TokenProvider tokenProvider, String token) {

            }

            @Override
            public void onPassed(CanAuth canAuth) {

            }

            @Override
            public void onFailed(Exception ex) {

            }
        };
    }

    public SpringGatewayAuthFilter(TokenProvider tokenProvider, Class<T> canAuthConcreteClass, AuthFilterHook hook) {
        this.tokenProvider = tokenProvider;
        this.canAuthConcreteClass = canAuthConcreteClass;
        this.hook = hook;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String header = exchange.getRequest().getHeaders().getFirst(tokenProvider.getHeader());

        if (header == null || !header.startsWith(tokenProvider.getPrefix())) {
            hook.onFailed(new Exception("Invalid HTTP header for authentication"));
            return chain.filter(exchange);
        }

        try {
            String token = header.replace(tokenProvider.getPrefix(), "");
            hook.beforeVerify(tokenProvider, token);
            tokenProvider.validateToken(token);
            T canAuthConcrete = tokenProvider.getCredential(token, canAuthConcreteClass);
            List<SimpleGrantedAuthority> authorities = canAuthConcrete
                    .authorities()
                    .stream().map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            Object principle = canAuthConcrete.principle();
            Authentication auth = new UsernamePasswordAuthenticationToken(principle, canAuthConcrete, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            hook.onPassed(canAuthConcrete);
        } catch (Exception e) {
            hook.onFailed(e);
            SecurityContextHolder.clearContext();
        }
        return chain.filter(exchange);
    }
}
