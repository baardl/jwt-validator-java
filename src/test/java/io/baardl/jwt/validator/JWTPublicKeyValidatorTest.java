package io.baardl.jwt.validator;

import org.jose4j.jwk.JsonWebKey;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class JWTPublicKeyValidatorTest {

    private String jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"nbCwW11w3XkB-xUaXwKRSLjMHGQ\"," +
            "\"x5t\":\"nbCwW11w3XkB-xUaXwKRSLjMHGQ\",\"n\":\"u98KvoUHfs2z2YJyfkJzaGFYM58eD0epHfETTwNDl6AL_cTfOklcxM4jrLWvVqqp2sHaH0gFpYPyovN-" +
            "_akmE_4fkc0Vw_wGM5jDP-jnOJ1vBvbFoF7uBAy4r3ln2ey1PoGUhpkXdDawhIfdAbc7WLtyopHNWQXI336rXiwjvcjL8dHhievDOktsAsilADP5wJT0lyTifONPZOq-" +
            "XWCw9FtXAQr7DniOC5uDuUaL0mM1UJChiCrDmFOAf6CNdu2SwLinXYauqM9ORElKYEChoEfi51fcsmlsn4mtNPkxstvR7OJiJBpvk7FLeiaBtMnsO5x30DPgrhAagrVn3IaKRQ\"," +
            "\"e\":\"AQAB\",\"x5c\":[\"MIIDBTCCAe2gAwIBAgIQV68hSN9DrrlCaA3NJ0bnfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MTExMTAwMDAwMFoXDTIwMTExMTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvfCr6FB37Ns9mCcn5Cc2hhWDOfHg9HqR3xE08DQ5egC/3E3zpJXMTOI6y1r1aqqdrB2h9IBaWD8qLzfv2pJhP+H5HNFcP8BjOYwz/o5zidbwb2xaBe7gQMuK95Z9nstT6BlIaZF3Q2sISH3QG3O1i7cqKRzVkFyN9+q14sI73Iy/HR4YnrwzpLbALIpQAz+cCU9Jck4nzjT2Tqvl1gsPRbVwEK+w54jgubg7lGi9JjNVCQoYgqw5hTgH+gjXbtksC4p12GrqjPTkRJSmBAoaBH4udX3LJpbJ+JrTT5MbLb0eziYiQab5OxS3omgbTJ7Ducd9Az4K4QGoK1Z9yGikUCAwEAAaMhMB8wHQYDVR0OBBYEFGWLmYFSm5Exg9VcAGSg5sFE1mXgMA0GCSqGSIb3DQEBCwUAA4IBAQB0yTGzyhx+Hz2vwBSo5xCkiIom6h7b946KKiWvgBLeOvAuxOsB15N+bbf51sUfUJ6jBaa1uJjJf27dxwH0oUe2fcmEN76QSrhULYe+k5yyJ7vtCnd6sHEfn9W6iRozv0cb48tESOTlFuwbYDVW+YZxzM9EQHC32CjugURzuN9/rf6nJ9etSeckRMO8QPqyIi4e5sGSDYExxNs7J4prhIbtYT4NRiqc4nWzA/p5wSYOUgAZMSTLD/beSI81UN1Ao9VBBJu3v83d62WL3zHSbpUwtG/utNhSi/n/7Q94claEWJVhBx6LiA1hrU6YZkjRGqBOrWIZkSkh75xW6Xujocy4\"],\"issuer\":\"https://login.microsoftonline.com/9d2ac018-e843-4e14-9e2b-4e0ddac75450/v2.0\"},{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"-sxMJMLCIDWMTPvZyJ6tx-CDxw0\",\"x5t\":\"-sxMJMLCIDWMTPvZyJ6tx-CDxw0\",\"n\":\"rxlPnqW6fNuCbdrhDEzwGJVux3iPvtt_8r-uHHIKa7C_b_ux5hewNMS91SgUPZOrsqb54uHj_7INWKqKEtFc4YP83Fhss_uO_mT97czENs4zWaSN9Eww_Fz36xq_uZ65750lHKwXQJ1A_pe-VOgNlPg8ECi7meQDJ05r838eu1jpKFjxkQrdRFTLgYtRQ7TxX-zzRyoRR8iqJc6Rvnijh19-YfWtBsCI1r127SFakUBrY_ZKsKyE9KNWUL7H65EyFRNgK80XfYvhQlGw3-Ajf28fi71wW-BypK1bTCArzwX7zgF3H6P1u8PKosSOSN_Q9-Qc9X-R_Y-3bOpOIiLOvw\",\"e\":\"AQAB\",\"x5c\":[\"MIIDBTCCAe2gAwIBAgIQKOfEJNDyDplBSXKYcM6UcjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MTIyMjAwMDAwMFoXDTIwMTIyMjAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8ZT56lunzbgm3a4QxM8BiVbsd4j77bf/K/rhxyCmuwv2/7seYXsDTEvdUoFD2Tq7Km+eLh4/+yDViqihLRXOGD/NxYbLP7jv5k/e3MxDbOM1mkjfRMMPxc9+sav7meue+dJRysF0CdQP6XvlToDZT4PBAou5nkAydOa/N/HrtY6ShY8ZEK3URUy4GLUUO08V/s80cqEUfIqiXOkb54o4dffmH1rQbAiNa9du0hWpFAa2P2SrCshPSjVlC+x+uRMhUTYCvNF32L4UJRsN/gI39vH4u9cFvgcqStW0wgK88F+84Bdx+j9bvDyqLEjkjf0PfkHPV/kf2Pt2zqTiIizr8CAwEAAaMhMB8wHQYDVR0OBBYEFC//HOy7pEIKtnpMj4bEMA3oJ39uMA0GCSqGSIb3DQEBCwUAA4IBAQAIYxZXIpwUX8HjSKWUMiyQEn0gRizAyqQhC5wdWOFCBIZPJs8efOkGTsBg/hA+X1fvN6htcBbJRfFfDlP/LkLIVNv2zX4clGM20YhY8FQQh9FWs5qchlnP4lSk7UmScxgT3a6FG3OcLToukNoK722Om2yQ1ayWtn9K82hvZl5L3P8zYaG1gbHPGW5VlNXds60jIpcSWLdU2hacYmwz4pPQyvNOW68aK/Y/tWrJ3DKrf1feDbmm7O5kpWVYWRpah+i6ePjELNkc2Jr+2DchBQTIh9Fxe8sz+9iOyLh9tubMJ+7RTs/ksK0sQ1NVScGFxK+o5hFOOMK7y/F5r467jHez\"],\"issuer\":\"https://login.microsoftonline.com/9d2ac018-e843-4e14-9e2b-4e0ddac75450/v2.0\"},{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"M6pX7RHoraLsprfJeRCjSxuURhc\",\"x5t\":\"M6pX7RHoraLsprfJeRCjSxuURhc\",\"n\":\"xHScZMPo8FifoDcrgncWQ7mGJtiKhrsho0-uFPXg-OdnRKYudTD7-Bq1MDjcqWRf3IfDVjFJixQS61M7wm9wALDj--lLuJJ9jDUAWTA3xWvQLbiBM-gqU0sj4mc2lWm6nPfqlyYeWtQcSC0sYkLlayNgX4noKDaXivhVOp7bwGXq77MRzeL4-9qrRYKjuzHfZL7kNBCsqO185P0NI2Jtmw-EsqYsrCaHsfNRGRrTvUHUq3hWa859kK_5uNd7TeY2ZEwKVD8ezCmSfR59ZzyxTtuPpkCSHS9OtUvS3mqTYit73qcvprjl3R8hpjXLb8oftfpWr3hFRdpxrwuoQEO4QQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIC8TCCAdmgAwIBAgIQfEWlTVc1uINEc9RBi6qHMjANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTgxMDE0MDAwMDAwWhcNMjAxMDE0MDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEdJxkw+jwWJ+gNyuCdxZDuYYm2IqGuyGjT64U9eD452dEpi51MPv4GrUwONypZF/ch8NWMUmLFBLrUzvCb3AAsOP76Uu4kn2MNQBZMDfFa9AtuIEz6CpTSyPiZzaVabqc9+qXJh5a1BxILSxiQuVrI2BfiegoNpeK+FU6ntvAZervsxHN4vj72qtFgqO7Md9kvuQ0EKyo7Xzk/Q0jYm2bD4SypiysJoex81EZGtO9QdSreFZrzn2Qr/m413tN5jZkTApUPx7MKZJ9Hn1nPLFO24+mQJIdL061S9LeapNiK3vepy+muOXdHyGmNctvyh+1+laveEVF2nGvC6hAQ7hBAgMBAAGjITAfMB0GA1UdDgQWBBQ5TKadw06O0cvXrQbXW0Nb3M3h/DANBgkqhkiG9w0BAQsFAAOCAQEAI48JaFtwOFcYS/3pfS5+7cINrafXAKTL+/+he4q+RMx4TCu/L1dl9zS5W1BeJNO2GUznfI+b5KndrxdlB6qJIDf6TRHh6EqfA18oJP5NOiKhU4pgkF2UMUw4kjxaZ5fQrSoD9omjfHAFNjradnHA7GOAoF4iotvXDWDBWx9K4XNZHWvD11Td66zTg5IaEQDIZ+f8WS6nn/98nAVMDtR9zW7Te5h9kGJGfe6WiHVaGRPpBvqC4iypGHjbRwANwofZvmp5wP08hY1CsnKY5tfP+E2k/iAQgKKa6QoxXToYvP7rsSkglak8N5g/+FJGnq4wP6cOzgZpjdPMwaVt5432GA==\"],\"issuer\":\"https://login.microsoftonline.com/9d2ac018-e843-4e14-9e2b-4e0ddac75450/v2.0\"}]}";
    private JWTPublicKeyValidator validator;

    @Before
    public void setUp() throws Exception {
        validator = new JWTPublicKeyValidator(jwksJson);
    }

    @Test
    public void fetchJwksFromUri() {
    }

    @Test
    public void buildFromJson() {
        assertNotNull(validator);
        assertNotNull(validator.getJwks());

    }

    @Test
    public void findKey() {
        String keyId = "nbCwW11w3XkB-xUaXwKRSLjMHGQ";
        String keyType = "RSA";
        String use = "sig";
        String algorithm = null;
        JsonWebKey key = validator.findKeyById(keyId, keyType, use, algorithm);
        assertNotNull(key);
    }
}