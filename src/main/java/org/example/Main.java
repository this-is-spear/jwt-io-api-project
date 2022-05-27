package org.example;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Map;

public class Main {
    private final static JwtProvider jwtProvider = new JwtProvider();

    public static void main(String[] args) throws InterruptedException {
        Authentication authentication = new FakeAuthentication();
        String token = jwtProvider.encode(authentication);

        if (jwtProvider.verify(token)) {
            DecodedJWT jwt = jwtProvider.decode(token);
            Map<String, Claim> decode = jwt.getClaims();
            for (Map.Entry<String, Claim> stringClaimEntry : decode.entrySet()) {
                System.out.println(stringClaimEntry.getKey() + " : " + stringClaimEntry.getValue());
            }

            System.out.println("jwt getExpiresAt = " + jwt.getExpiresAt());
        }
    }
}
