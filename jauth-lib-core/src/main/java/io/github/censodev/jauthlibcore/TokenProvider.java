package io.github.censodev.jauthlibcore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.io.IOException;
import java.util.Date;

@SuperBuilder(toBuilder = true)
@NoArgsConstructor
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

    @Builder.Default
    private String secret = "qwertyuiopasdfghjklzxcvbnm1!2@3#4$5%6^7&8*9(0)-_=+";

    @Builder.Default
    private String credentialClaimKey = "credential";

    @Builder.Default
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @Builder.Default
    private ObjectMapper mapper = JsonMapper.builder()
            .findAndAddModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    public <T extends Credential> String generateAccessToken(T credential) throws JsonProcessingException {
        return generateToken(credential, expireInMillisecond);
    }

    public <T extends Credential> String generateRefreshToken(T credential) throws JsonProcessingException {
        return generateToken(credential, refreshTokenExpireInMillisecond);
    }

    public <T extends Credential> T getCredential(String token, Class<T> tClass) throws IOException {
        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        return mapper.readValue(String.valueOf(claims.get(credentialClaimKey)), tClass);
    }

    public void validateToken(String token) throws
            MalformedJwtException,
            ExpiredJwtException,
            UnsupportedJwtException,
            IllegalArgumentException,
            SignatureException {
        Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
    }

    private <T extends Credential> String generateToken(T credential, Integer expireInMillisecond) throws JsonProcessingException {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expireInMillisecond);
        return Jwts.builder()
                .setSubject(credential.getSubject())
                .claim(credentialClaimKey, mapper.writeValueAsString(credential))
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(signatureAlgorithm, secret)
                .compact();
    }
}
