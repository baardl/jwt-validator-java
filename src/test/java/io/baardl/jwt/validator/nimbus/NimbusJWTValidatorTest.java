package io.baardl.jwt.validator.nimbus;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import io.baardl.jwt.validator.utils.Configuration;

public class NimbusJWTValidatorTest {

	private String userToken = null;

	@Before
	public void setUp() throws Exception {
		userToken = Configuration.getString("base64UrlEncodedUserToken");
	}

	@Test
	public void validateUserToken() {
		String publicKeyJson = "{\n" +
									   "\"kty\": \"RSA\",\n" +
									   "\"use\": \"sig\",\n" +
									   "\"kid\": \"-sxMJMLCIDWMTPvZyJ6tx-CDxw0\",\n" +
									   "\"x5t\": \"-sxMJMLCIDWMTPvZyJ6tx-CDxw0\",\n" +
									   "\"n\": \"rxlPnqW6fNuCbdrhDEzwGJVux3iPvtt_8r-uHHIKa7C_b_ux5hewNMS91SgUPZOrsqb54uHj_7INWKqKEtFc4YP83Fhss_uO_mT97czENs4zWaSN9Eww_Fz36xq_uZ65750lHKwXQJ1A_pe-VOgNlPg8ECi7meQDJ05r838eu1jpKFjxkQrdRFTLgYtRQ7TxX-zzRyoRR8iqJc6Rvnijh19-YfWtBsCI1r127SFakUBrY_ZKsKyE9KNWUL7H65EyFRNgK80XfYvhQlGw3-Ajf28fi71wW-BypK1bTCArzwX7zgF3H6P1u8PKosSOSN_Q9-Qc9X-R_Y-3bOpOIiLOvw\",\n" +
									   "\"e\": \"AQAB\",\n" +
									   "\"x5c\": [\n" +
									   "\"MIIDBTCCAe2gAwIBAgIQKOfEJNDyDplBSXKYcM6UcjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MTIyMjAwMDAwMFoXDTIwMTIyMjAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8ZT56lunzbgm3a4QxM8BiVbsd4j77bf/K/rhxyCmuwv2/7seYXsDTEvdUoFD2Tq7Km+eLh4/+yDViqihLRXOGD/NxYbLP7jv5k/e3MxDbOM1mkjfRMMPxc9+sav7meue+dJRysF0CdQP6XvlToDZT4PBAou5nkAydOa/N/HrtY6ShY8ZEK3URUy4GLUUO08V/s80cqEUfIqiXOkb54o4dffmH1rQbAiNa9du0hWpFAa2P2SrCshPSjVlC+x+uRMhUTYCvNF32L4UJRsN/gI39vH4u9cFvgcqStW0wgK88F+84Bdx+j9bvDyqLEjkjf0PfkHPV/kf2Pt2zqTiIizr8CAwEAAaMhMB8wHQYDVR0OBBYEFC//HOy7pEIKtnpMj4bEMA3oJ39uMA0GCSqGSIb3DQEBCwUAA4IBAQAIYxZXIpwUX8HjSKWUMiyQEn0gRizAyqQhC5wdWOFCBIZPJs8efOkGTsBg/hA+X1fvN6htcBbJRfFfDlP/LkLIVNv2zX4clGM20YhY8FQQh9FWs5qchlnP4lSk7UmScxgT3a6FG3OcLToukNoK722Om2yQ1ayWtn9K82hvZl5L3P8zYaG1gbHPGW5VlNXds60jIpcSWLdU2hacYmwz4pPQyvNOW68aK/Y/tWrJ3DKrf1feDbmm7O5kpWVYWRpah+i6ePjELNkc2Jr+2DchBQTIh9Fxe8sz+9iOyLh9tubMJ+7RTs/ksK0sQ1NVScGFxK+o5hFOOMK7y/F5r467jHez\"\n" +
									   "],\n" +
									   "\"issuer\": \"https://login.microsoftonline.com/9d2ac018-e843-4e14-9e2b-4e0ddac75450/v2.0\"\n" +
									   "}";
		boolean isValid = NimbusJWTValidator.validateUserToken(userToken, publicKeyJson);
		assertTrue(isValid);
	}
}