package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.util.Map;
import java.util.stream.Collectors;

public class JwtProvider {
    private static final String ISSUER = "auth0";
    private static final String SECRET_KEY = "secret";
    private static final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
    private static final JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).build();
    private static final String AUTHORITIES_KEY = "Auth";

    public String encode(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(","));

        System.out.println(authorities);

        try {
            String token = JWT.create()
                .withSubject((String) authentication.getPrincipal())
                .withClaim(AUTHORITIES_KEY, authorities)
                .withIssuer(ISSUER)
                .sign(algorithm);
            System.out.println(token);
            return token;
        } catch (JWTCreationException exception) {
            return "";
        }
    }

    public Map<String, Claim> decode(String token) {
        DecodedJWT jwt = verifier.verify(token);
        Map<String, Claim> claims = jwt.getClaims();
        return claims;
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
