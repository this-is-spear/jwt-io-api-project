package org.example;

import com.auth0.jwt.interfaces.Claim;

import java.util.Map;

public class Main {
    private final static JwtProvider jwtProvider = new JwtProvider();

    public static void main(String[] args) {
        Authentication authentication = new FakeAuthentication();
        String token = jwtProvider.encode(authentication);

        if (jwtProvider.verify(token)) {
            Map<String, Claim> decode = jwtProvider.decode(token);
            for (Map.Entry<String, Claim> stringClaimEntry : decode.entrySet()) {
                System.out.println(stringClaimEntry.getKey() + " : " + stringClaimEntry.getValue());
            }
        }
    }
}
