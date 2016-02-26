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

import static com.jayway.restassured.RestAssured.given;
import static org.junit.Assert.assertTrue;

import java.net.URL;

import org.hamcrest.Matchers;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ExtractableResponse;
import com.jayway.restassured.response.Response;

/**
 * TestImplicitFlow
 */
@RunWith(Arquillian.class)
public class TestRevokeToken {


    @Deployment
    public static Archive createDeployment() {

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(true, "de.adorsys.oauth.sample")
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
                .addAsWebInfResource("web.xml")
                .addAsWebInfResource("jboss-deployment-structure.xml")
                ;
    }
    
    @BeforeClass
    public static void setLogging(){
    	RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }
    
    @Test @RunAsClient
    public void testRevokeLoginSessionToken() throws Exception {
    	//create a token
        ExtractableResponse<Response> response = given()
        		.redirects().follow(false)
        		.formParam("j_username", "jduke")
        		.formParam("j_password", "1234")
                .when()
                .urlEncodingEnabled(false)
                .post(SampleRequest.AUTH_ENDPOINT + "?response_type=code&client_id=sample&redirect_uri=" + SampleRequest.SAMPLE_URL)
                .then().statusCode(302)
                .extract()
                
        ;

        String location = response.header("Location");

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
                   .body("login_session", Matchers.not(Matchers.isEmptyOrNullString()))
                   .body("expires_in", Matchers.not(Matchers.isEmptyOrNullString()))
                   .body("token_type", Matchers.is("Bearer"))
                   .header("Pragma", "no-cache")
                   .header("Cache-Control", "no-store")
                   .extract()
                   ;

        ;

        String accessToken = response.jsonPath().get("access_token");
        String loginSession = response.jsonPath().getString("login_session");
        
        //revoke the token
        given()
        		.redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .authentication().basic("sample", "password")
                .formParam("token", loginSession)
                .formParam("token_type_hint", "login_session")
                .formParam("username", "jduke")
                .formParam("password", "1234")
                .when()
                .post(SampleRequest.REVOKE_ENDPOINT)
                .then()
                .statusCode(200)
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract().response()
                ;
        
        //redirect to login
        given()
    	.log().ifValidationFails()
    			.redirects().follow(false)
                .authentication().oauth2(accessToken)
                .when()
                .get(SampleRequest.SAMPLE_URL)
                .then()
                .statusCode(302);
    }

    @Test @RunAsClient
    public void testRevokeToken() throws Exception {
    	//create a token
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
        String accessToken = response.jsonPath().getString("access_token");
        String refreshToken = response.jsonPath().getString("refresh_token");
        
        //revoke the token
        given()
        		.redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .authentication().basic("sample", "password")
                .formParam("token", refreshToken)
                .formParam("username", "jduke")
                .formParam("password", "1234")
                .when()
                .post(SampleRequest.REVOKE_ENDPOINT)
                .then()
                .statusCode(200)
                .header("Pragma", "no-cache")
                .header("Cache-Control", "no-store")
                .extract().response()
                ;
        
        //redirect to login
        given()
    	.log().ifValidationFails()
    			.redirects().follow(false)
                .authentication().oauth2(accessToken)
                .when()
                .get(SampleRequest.SAMPLE_URL)
                .then()
                .statusCode(302);
    }
}
