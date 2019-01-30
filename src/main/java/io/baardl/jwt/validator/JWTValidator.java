package io.baardl.jwt.validator;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.getLogger;

public class JWTValidator {
    private static final Logger log = getLogger(JWTValidator.class);


    public static boolean validateUserToken(String base64UrlEncodedUserToken, String jwksJson) {
        boolean isValid = false;
        // The complete JWS representation, or compact serialization, is string consisting of
        // three dot ('.') separated base64url-encoded parts in the form Header.Payload.Signature
        //compactSerialization = "eyJhbGciOiJFUzI1NiIsImtpZCI6InRoZSBrZXkifQ." +
        //                "UEFZTE9BRCE."+
        //                "Oq-H1lk5G0rl6oyNM3jR5S0-BZQgTlamIKMApq3RX8Hmh2d2XgB4scvsMzGvE-OlEmDY9Oy0YwNGArLpzXWyjw";
        String compactSerialization = base64UrlEncodedUserToken;

        // Create a new JsonWebSignature object
        JsonWebSignature jws = new JsonWebSignature();

        // Set the algorithm constraints based on what is agreed upon or expected from the sender
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,   AlgorithmIdentifiers.RSA_USING_SHA256));

        // Set the compact serialization on the JWS
        try {
            jws.setCompactSerialization(compactSerialization);

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwksJson);
            VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
            JsonWebKey jwk = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());

            // The verification key on the JWS is the public key from the JWK we pulled from the JWK Set.
            jws.setKey(jwk.getKey());

            isValid = jws.verifySignature();
        } catch (JoseException e) {
           log.debug("Failed to validate. \nuserToken: {}.\njwksJson: {}.\nReason: {}", base64UrlEncodedUserToken,jwksJson,e.getMessage());
        }

        return isValid;

    }
}
