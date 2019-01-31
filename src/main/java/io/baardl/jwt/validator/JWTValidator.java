package io.baardl.jwt.validator;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;

import java.security.Key;

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
//        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,   AlgorithmIdentifiers.RSA_USING_SHA256));

        // Set the compact serialization on the JWS
        try {
            jws.setCompactSerialization(compactSerialization);

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwksJson);
            VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
            JsonWebKey jwk = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());

            // The verification key on the JWS is the public key from the JWK we pulled from the JWK Set.
            Key publicKey = jwk.getKey();
            jws.setKey(publicKey);

            isValid = jws.verifySignature();
        } catch (JoseException e) {
           log.debug("Failed to validate. \nuserToken: {}.\njwksJson: {}.\nReason: {}", base64UrlEncodedUserToken,jwksJson,e.getMessage());
        }

        return isValid;

    }

    static JsonWebSignature buildJwsFromUserToken(String jwt) {
        JsonWebSignature jws = new JsonWebSignature();
        try {
            jws.setCompactSerialization(jwt);
        } catch (JoseException e) {
            log.debug("Failed to build compactserialization from jwt {}. \nReason {}", jwt, e.getMessage());
            jws = null;
        }
        return jws;
    }

    static JwtClaims parseJWT(String jwt, JsonWebKey publicKey) {
        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
        // be used to validate and process the JWT.
        // The specific validation requirements for a JWT are context dependent, however,
        // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
        // and audience that identifies your system as the intended recipient.
        // If the JWT is encrypted too, you need only provide a decryption key or
        // decryption key resolver to the builder.
        Key key = publicKey.getKey();
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKey(key) // verify the signature with the public key
                .setExpectedAudience(false, "")
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            log.info("JWT validation succeeded! " + jwtClaims);
            return jwtClaims;
        } catch (InvalidJwtException e) {
            // Programmatic access to (some) specific reasons for JWT invalidity is also possible
            // should you want different error handling behavior for certain conditions.

            // Whether or not the JWT has expired being one common reason for invalidity
            if (e.hasExpired()) {
                try {
                    log.warn("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
                } catch (MalformedClaimException e1) {
                    e1.printStackTrace();
                }
            } else {
                // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
                // Hopefully with meaningful explanations(s) about what went wrong.
                log.warn("Invalid JWT! " + e);
            }

            return null;
        }
    }

    public static JsonWebKey buildKey(String jwksJson, JsonWebSignature jws) {
        JsonWebKey key = null;
        try {
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwksJson);
            VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
            key = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());
        } catch (JoseException e) {
            e.printStackTrace();
        }
        return key;
    }
}
