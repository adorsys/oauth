package de.adorsys.oauth.sample;

import static com.jayway.restassured.RestAssured.given;

import org.hamcrest.Matchers;

/**
 * AuthorizedRequest
 */
public class SampleRequest {

    static String SAMPLE_URL     = "http://localhost:8280/sample/hello";
    static String AUTH_ENDPOINT  = "http://localhost:8280/oauth/api/auth";
    static String TOKEN_ENDPOINT = "http://localhost:8280/oauth/api/token";
    static String REVOKE_ENDPOINT = "http://localhost:8280/oauth/api/revoke";

    public static void verify(String accessToken) {
        given()
        	.log().ifValidationFails()
                    .authentication().oauth2(accessToken)
                    .when()
                    .get(SAMPLE_URL)
                    .then()
                    .statusCode(200)
                    .body(Matchers.containsString("Hello from jduke [ user admin ]"))
        ;
    }

}
