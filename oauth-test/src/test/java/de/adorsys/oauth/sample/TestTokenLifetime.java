package de.adorsys.oauth.sample;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;

import org.hamcrest.Matchers;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.TimeUnit;

import static com.jayway.restassured.RestAssured.given;

/**
 * TestTokenLifetime
 */
@SuppressWarnings("Duplicates")
@RunWith(Arquillian.class)
public class TestTokenLifetime {


    @Deployment
    public static Archive createDeployment() {

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(true, "de.adorsys.oauth.sample")
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
                .addAsWebInfResource("web.xml")
                .addAsWebInfResource("jboss-deployment-structure.xml")
                ;

        //        System.out.println(a.toString(true));
        //        return a;
    }

    @BeforeClass
    public static void setLogging(){
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }

    @Test @RunAsClient
    public void testTokenLifetime() throws Exception {

        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

        Response response = given()
                .redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .authentication().basic("sample", "password")
                .formParam("grant_type", "password")
                .formParam("username", "jduke")
                .formParam("password", "1234")
                .when()
                .post(SampleRequest.TOKEN_ENDPOINT)
                .then()
                .statusCode(200)
                .body("access_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("refresh_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("token_type", Matchers.is("Bearer"))
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract().response()
                ;

        System.out.println(response.asString());

        String accessToken = response.jsonPath().getString("access_token");

        int expiresIn = Integer.valueOf(response.jsonPath().getString("expires_in"));

        SampleRequest.verify(accessToken);

        System.out.printf("wait %d seconds ...%n", expiresIn - 5);
        TimeUnit.SECONDS.sleep(expiresIn - 5);

        SampleRequest.verify(accessToken);

        System.out.printf("wait %d seconds ...%n", 6);
        TimeUnit.SECONDS.sleep(6);

        SampleRequest.verify(accessToken, "Simple Login Page");
    }
}