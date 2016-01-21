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

import com.jayway.restassured.config.RestAssuredConfig;
import com.jayway.restassured.response.Response;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URL;

import static com.jayway.restassured.RestAssured.given;
import static com.jayway.restassured.config.RedirectConfig.redirectConfig;
import static com.jayway.restassured.config.RestAssuredConfig.newConfig;
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
                ;
    }

    @Test @RunAsClient
    public void testAuthCode() throws Exception {

        RestAssuredConfig config = newConfig().redirect(redirectConfig().followRedirects(false));

        Response response = given()
                          //  .log().all()
                            .config(config)
                            .when()
                            .get(SampleRequest.SAMPLE_URL)
                            ;

        // redirect zum IDP
        response.then().statusCode(302);
        String location = response.then().extract().header("Location");

        assertTrue(location.contains("oauth/api/auth"));

        response = given()
                //  .log().all()
                .when()
                .get(location)
                ;

        response.then().statusCode(401);

        response = given()
                //.log().all()
                .config(config)
                .auth().preemptive().basic("test", "1234")
                .when()
                .get(location)
        ;

        response.then().statusCode(302);
        location = response.then().extract().header("Location");

        URL idpUrl = new URL(location);

        assertTrue(location.contains("?code="));

        String authCode = location.substring(location.indexOf("?") + 6);

        response = given()
                 //  .log().all()
                   .config(config)
                   .contentType("application/x-www-form-urlencoded")
                   .formParam("grant_type", "authorization_code")
                   .formParam("code", authCode)
                   .formParam("redirect_uri", SampleRequest.SAMPLE_URL)
                   .formParam("client_id", "sample")
                   .when()
                   .post(String.format("http://%s:%d/oauth/api/token", idpUrl.getHost(), idpUrl.getPort()))
                   ;

        response.then().statusCode(200);

        String accessToken = response.jsonPath().get("access_token");
        String refreshToken = response.jsonPath().get("refresh_token");

        System.out.printf("accessToken %s refreshToken %s %n", accessToken, refreshToken);

        SampleRequest.verify(accessToken);

    }
}
