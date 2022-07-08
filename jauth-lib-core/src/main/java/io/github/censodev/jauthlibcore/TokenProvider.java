package io.github.censodev.jauthlibcore;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;

@SuperBuilder(toBuilder = true)
@Getter
public class TokenProvider {
    @Builder.Default
    private String header = "Authorization";

    @Builder.Default
    private String prefix = "Bearer ";

    @Builder.Default
    private Integer expireInMillisecond = 3_600_000;

    @Builder.Default
    private Integer refreshTokenExpireInMillisecond = 86_400_000;

    @NonNull
    private String secret;

    @Builder.Default
    private String credentialClaimKey = "credential";

    @Builder.Default
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @Builder.Default
    private ObjectMapper mapper = JsonMapper.builder()
            .findAndAddModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    public <T extends Credential> String generateAccessToken(T credential) {
        return generateToken(credential, expireInMillisecond);
    }

    public <T extends Credential> String generateRefreshToken(T credential) {
        return generateToken(credential, refreshTokenExpireInMillisecond);
    }

    public <T extends Credential> T getCredential(String token, Class<T> tClass) {
        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        Map<?, ?> credInMap = Jwts.parserBuilder()
                .deserializeJsonWith(new JacksonDeserializer<>(mapper))
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get(credentialClaimKey, Map.class);
        return mapper.convertValue(credInMap, tClass);
    }

    public void validateToken(String token) throws JwtException {
        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    private <T extends Credential> String generateToken(T credential, Integer expireInMillisecond) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expireInMillisecond);
        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .serializeToJsonWith(new JacksonSerializer<>(mapper))
                .setSubject(credential.getSubject())
                .claim(credentialClaimKey, credential)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, signatureAlgorithm)
                .compact();
    }
}
