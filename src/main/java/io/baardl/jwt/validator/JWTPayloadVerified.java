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

public class JWTPayloadVerified {
    private static final Logger log = getLogger(JWTPayloadVerified.class);

    public static String parseUserFromUserToken(String base64UrlEncodedUserToken, String jwksJson) {
        String user = null;
//        if (JWTValidator.validateUserToken(base64UrlEncodedUserToken, jwksJson)) {
            user = findPayloadFromUserToken(base64UrlEncodedUserToken, jwksJson);
//        }
        return user;
    }




    static String findPayloadFromUserToken(String base64UrlEncodedUserToken, String jwksJson) {
        String payload = null;
        JsonWebSignature jws = new JsonWebSignature();

        // Set the algorithm constraints based on what is agreed upon or expected from the sender
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,   AlgorithmIdentifiers.RSA_USING_SHA256));

        // Set the compact serialization on the JWS
        try {
            jws.setCompactSerialization(base64UrlEncodedUserToken);

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwksJson);
            VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
            JsonWebKey jwk = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());

            // The verification key on the JWS is the public key from the JWK we pulled from the JWK Set.
            jws.setKey(jwk.getKey());

            boolean isValid = jws.verifySignature();

            if (isValid) {
                payload = jws.getPayload();
            }
        } catch (JoseException e) {
            log.debug("Failed to find payload. \nuserToken: {}.\nReason: {}", base64UrlEncodedUserToken,e.getMessage());
        }

        return payload;
    }

}
