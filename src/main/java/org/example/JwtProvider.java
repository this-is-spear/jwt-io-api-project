package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.util.Date;
import java.util.stream.Collectors;

public class JwtProvider {
    private static final String ISSUER = "auth0";
    private static final String SECRET_KEY = "secret";
    private static final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
    private static final JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).acceptLeeway(1).acceptExpiresAt(5).build();
    private static final String AUTHORITIES_KEY = "Auth";
    public static final String DELIMITER = ",";
    private final long tokenValidityInMilliseconds = 5 * 1000;

    public String encode(Authentication authentication) {
        String authorities = getAuthorities(authentication);
        try {
            long now = (new Date()).getTime();
            Date validity = new Date(now + this.tokenValidityInMilliseconds);

            String token = JWT.create()
                .withSubject((String) authentication.getPrincipal())
                .withClaim(AUTHORITIES_KEY, authorities)
                .withIssuer(ISSUER)
                .withExpiresAt(validity)
                .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            return "";
        }
    }

    private String getAuthorities(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(DELIMITER));
        return authorities;
    }

    public DecodedJWT decode(String token) {
        return verifier.verify(token);
    }

    public boolean verify(String token) {
        try {
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }
}
