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
import com.jayway.restassured.filter.log.LogDetail;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static com.jayway.restassured.RestAssured.given;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * TestPasswordFlow
 */
@RunWith(Arquillian.class)
public class TestSpecialCharacter {

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

    @Test
    @RunAsClient
    public void testSpecialCharacter() throws Exception {

        Properties properties = new Properties();
        properties.load(getClass().getResourceAsStream("/users.properties"));

        List<String> errors = new ArrayList<>();

        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            try {
                login((String) entry.getKey(), (String) entry.getValue());
            } catch (Throwable e) {
                errors.add(String.format("Login failed %s %s : %s", entry.getKey(), entry.getValue(), e.getMessage()));
            }
        }

        if (0 < errors.size()) {
            for (String error : errors) {
                System.out.println(error);
            }
            fail();
        }
    }

    private void login(String user, String password) throws Exception {

        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

        Response response = given()
                .redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .authentication().basic("sample", "password")
                .formParam("grant_type", "password")
                .formParam("username", user)
                .formParam("password", password)
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

        assertNotNull(accessToken);
        assertNotNull(refreshToken);

        System.out.printf("Login success for %s %s%n", user, password);

    }

    @BeforeClass
    public static void setLogging() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails(LogDetail.METHOD);
    }

}
