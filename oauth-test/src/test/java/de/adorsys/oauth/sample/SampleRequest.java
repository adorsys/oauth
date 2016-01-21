package de.adorsys.oauth.sample;

import com.jayway.restassured.response.Response;

import static com.jayway.restassured.RestAssured.given;
import static org.junit.Assert.assertTrue;

/**
 * AuthorizedRequest
 */
public class SampleRequest {

    static String SAMPLE_URL     = "http://localhost:8280/sample/hello";
    static String AUTH_ENDPOINT  = "http://localhost:8280/oauth/api/auth";
    static String TOKEN_ENDPOINT = "http://localhost:8280/oauth/api/token";

    public static void verify(String accessToken) {
        Response response = given()
                    //  .log().all()
                    .authentication().oauth2(accessToken)
                    .when()
                    .get(SAMPLE_URL)
        ;

        response.then().statusCode(200);
        System.out.println(response.asString());

        assertTrue(response.asString().contains("Hello from jduke [ user admin ]"));
    }

}
