package io.baardl.jwt.validator.nimbus;


import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

public class NimbusJWTValidator {
	private static final Logger log = LoggerFactory.getLogger(NimbusJWTValidator.class);

	public static boolean validateUserToken(String base64UrlEncodedUserToken, String publicKeyJson) {
		boolean isValid = false;
		RSAKey publicKey = null;

		try {
			publicKey = RSAKey.parse(publicKeyJson);
		} catch (ParseException e) {
			log.debug("Failed to parse the publicKeyJson {}. \nReason: {}", publicKeyJson, e.getMessage());
		}
		SignedJWT signedJWT = null;
		try {
			signedJWT = SignedJWT.parse(base64UrlEncodedUserToken);
		} catch (ParseException e) {
			log.debug("Failed to parse the base64UrlEncodedUserToken {}. \nReason: {}", base64UrlEncodedUserToken, e.getMessage());
		}
		JWSVerifier verifier = null;
		try {
			verifier = new RSASSAVerifier(publicKey);
		} catch (JOSEException e) {
			log.debug("Failed ot build verifier from publicKey {}. Reason {}", publicKey, e.getMessage());
		}
		try {
			isValid = signedJWT.verify(verifier);
		} catch (JOSEException e) {
			log.debug("Failed to verify. Reason: {}", e.getMessage());
		}
		return isValid;
	}
}
