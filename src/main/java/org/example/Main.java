package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Main {

    private static final String ISSUER = "auth0";
    private static final String SECRET_KEY = "secret";
    private static final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
    //verifier
    private static final JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).build();
    private static final String AUTHORITIES_KEY = "Auth";


    public static void main(String[] args) {
        Authentication authentication = new FakeAuthentication();
        String token = encode(authentication);

        DecodedJWT decodedJWT = decode(token);

        Map<String, Claim> claims = decodedJWT.getClaims();
        for (Map.Entry<String, Claim> stringClaimEntry : claims.entrySet()) {
            System.out.println(stringClaimEntry.getKey() + " : " + stringClaimEntry.getValue());
        }
    }

    private static String encode(Authentication authentication) {
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
            //Invalid Signing configuration / Couldn't convert Claims.
            return "";
        }
    }

    private static DecodedJWT decode(String token) {
        try {
            DecodedJWT jwt = verifier.verify(token);
            return jwt;
        } catch (JWTVerificationException exception) {
            //Invalid signature/claims
            return null;
        }
    }
}
