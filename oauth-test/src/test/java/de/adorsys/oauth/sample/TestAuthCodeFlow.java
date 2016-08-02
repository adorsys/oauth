/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.adorsys.oauth.sample;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ExtractableResponse;
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

import java.net.URL;
import java.util.Map;

import static com.jayway.restassured.RestAssured.given;
import static org.junit.Assert.assertTrue;

/**
 * TestAuthCode
 */
@RunWith(Arquillian.class)
public class TestAuthCodeFlow {

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
    public void testAuthCode() throws Exception {
        ExtractableResponse<Response> response = given()
                .redirects().follow(false)
                .when()
                .get(SampleRequest.SAMPLE_URL)
                .then()
                .statusCode(302)
                .header("Location", Matchers.containsString("oauth/api/auth"))
                .extract();


        // redirect zum IDP
        String location = response.header("Location");

        given()
                .when()
                .get(location)
                .then()
                .statusCode(200)
                .body(Matchers.containsString("Hello, please log in"))
        ;


        response = given()
        		.log().ifValidationFails()
                .redirects().follow(false)
                .formParam("j_username", "wilduser")
                .formParam("j_password", "1234?")
                .when()
                .urlEncodingEnabled(false)
                .post(location)
                .then().statusCode(302)
                .extract()

        ;

        location = response.header("Location");

        URL idpUrl = new URL(location);

        assertTrue(location.contains("?code="));

        String authCode = location.substring(location.indexOf("?") + 6);

        response = given()
                .log().all()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(200)
                .body("access_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("refresh_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("token_type", Matchers.is("Bearer"))
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract()
        ;



        String accessToken = response.jsonPath().get("access_token");
        String refreshToken = response.jsonPath().get("refresh_token");

        System.out.printf("accessToken %s refreshToken %s %n", accessToken, refreshToken);

        SampleRequest.verifyWilduser(accessToken);
    }

    @Test @RunAsClient
    public void testRememberMeAuthCode() throws Exception {


        ExtractableResponse<Response> response = given()
                .redirects().follow(false)
                .when()
                .get(SampleRequest.SAMPLE_URL)
                .then()
                .statusCode(302)
                .header("Location", Matchers.containsString("oauth/api/auth"))
                .extract();


        // redirect zum IDP
        String location = response.header("Location");

        given()
                .when()
                .get(location)
                .then()
                .statusCode(200)
                .body(Matchers.containsString("Hello, please log in"))
        ;


        response = given()
                .formParam("j_username", "jduke")
                .formParam("j_password", "1234")
                .when()
                .post(location)
                .then()
                .statusCode(302)
                .extract()

        ;

        Map<String, String> rememberCookie = response.cookies();
        URL idpUrl = new URL(location);

        response = given()
                .log().all()
                .redirects().follow(false)
                .cookies(rememberCookie)
                .when()
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .statusCode(302).extract()
        ;

        location = response.header("Location");
        assertTrue(location.contains("?code="));
        String authCode = location.substring(location.indexOf("?") + 6);

        response = given()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(200)
                .body("access_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("refresh_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("token_type", Matchers.is("Bearer"))
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract()
        ;



        String accessToken = response.jsonPath().get("access_token");
        String refreshToken = response.jsonPath().get("refresh_token");

        System.out.printf("accessToken %s refreshToken %s %n", accessToken, refreshToken);

        SampleRequest.verify(accessToken);
    }

    @Test @RunAsClient
    public void testAuthCodeTwiceUsage() throws Exception {
        URL idpUrl = new URL(SampleRequest.SAMPLE_URL);
        String authCode = retrieveAuthCode();

        given()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(200)
                .body("access_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("refresh_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("token_type", Matchers.is("Bearer"))
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
        ;

        given()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(400);

    }

    @Test @RunAsClient
    public void testInvaidRedirectUriForCode() throws Exception {
        String authCode = retrieveAuthCode();

        URL idpUrl = new URL(SampleRequest.SAMPLE_URL);
        given()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL + "&somethingelse")
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(400)
        ;

    }

    @Test @RunAsClient
    public void testInvaidClientIdForCode() throws Exception {
        String authCode = retrieveAuthCode();

        URL idpUrl = new URL(SampleRequest.SAMPLE_URL);
        given()
                .authentication().basic("otherClient", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", SampleRequest.SAMPLE_URL + "&somethingelse")
                .formParam("client_id", "wrongClintId")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(400)
        ;

    }

    private String retrieveAuthCode() {
        ExtractableResponse<Response> response = given()
                .redirects().follow(false)
                .when()
                .get(SampleRequest.SAMPLE_URL)
                .then()
                .statusCode(302)
                .header("Location", Matchers.containsString("oauth/api/auth"))
                .extract();


        // redirect zum IDP
        String location = response.header("Location");

        given()
                .when()
                .get(location)
                .then()
                .statusCode(200)
                .body(Matchers.containsString("Hello, please log in"))
        ;


        response = given()
                .formParam("j_username", "test")
                .formParam("j_password", "1234")
                .when()
                .urlEncodingEnabled(false)
                .post(location)
                .then().statusCode(302)
                .extract()

        ;

        location = response.header("Location");

        assertTrue(location.contains("?code="));

        return location.substring(location.indexOf("?") + 6);
    }


    @Test @RunAsClient
    public void testAuthCodeWithQueryParams() throws Exception {

        ExtractableResponse<Response> response = given()
                .redirects().follow(false)
                .when()
                .get(SampleRequest.SAMPLE_URL + "?ort=Erlangen&strasse=Unter+den+Palmen+3&vorname=Maximilian&context=kundenwelt&nachname=Mustermann&land=DE&plz=91056")
                .then()
                .statusCode(302)
                .header("Location", Matchers.containsString("oauth/api/auth"))
                .extract();


        // redirect zum IDP
        String location = response.header("Location");

        given()
                .when()
                .get(location)
                .then()
                .statusCode(200)
                .body(Matchers.containsString("Hello, please log in"))
        ;


        response = given()
                .log().ifValidationFails()
                .redirects().follow(false)
                .formParam("j_username", "wilduser")
                .formParam("j_password", "1234?")
                .when()
                .urlEncodingEnabled(false)
                .post(location)
                .then().statusCode(302)
                .extract()

        ;

        location = response.header("Location");

        URL idpUrl = new URL(location);

        assertTrue(location.contains("code="));
        int index = location.indexOf("&code=");

        String authCode = location.substring(index + 6);
        String originalUrl = location.substring(0, index);

        response = given()
                .log().all()
                .authentication().basic("sample", "password")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", authCode)
                .formParam("redirect_uri", originalUrl)
                .formParam("client_id", "sample")
                .when()
                .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                .then()
                .statusCode(200)
                .body("access_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("refresh_token", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                .body("token_type", Matchers.is("Bearer"))
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract()
        ;


        String accessToken = response.jsonPath().get("access_token");
        String refreshToken = response.jsonPath().get("refresh_token");

        System.out.printf("accessToken %s refreshToken %s %n", accessToken, refreshToken);

        SampleRequest.verifyWilduser(accessToken);
    }

}
