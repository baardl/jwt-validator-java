package io.baardl.jwt.validator;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;

import java.net.URI;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Validate based on public JWKS url
 */
public class JWTPublicKeyValidator {
    private static final Logger log = getLogger(JWTPublicKeyValidator.class);

    private String jwksJson = null;
    private URI jwksUri = null;
    private JsonWebKeySet jwks = null;

    public JWTPublicKeyValidator(String jwksJson) {
        this.jwksJson = jwksJson;
        jwks = buildFromJson(jwksJson);
    }

    public JWTPublicKeyValidator(URI jwksUri) {
        this.jwksUri = jwksUri;
        this.jwksJson = fetchJwksFromUri(jwksUri);
    }

    String fetchJwksFromUri(URI jwksUri) {
        //TODO
        return null;
    }

    JsonWebKeySet buildFromJson(String jwksJson) {
        try {
            jwks = new JsonWebKeySet(jwksJson);
        } catch (JoseException e) {
            log.debug("Failed to build jwks from {}, reason: {}", jwksJson, e.getMessage());
        }
        return jwks;
    }

    public String getJwksJson() {
        return jwksJson;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public JsonWebKeySet getJwks() {
        return jwks;
    }
}
