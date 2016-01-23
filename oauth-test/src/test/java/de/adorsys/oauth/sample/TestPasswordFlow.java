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

import static com.jayway.restassured.RestAssured.given;
import static com.jayway.restassured.config.RedirectConfig.redirectConfig;
import static com.jayway.restassured.config.RestAssuredConfig.newConfig;

/**
 * TestPasswordFlow
 */
@RunWith(Arquillian.class)
public class TestPasswordFlow {


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

    @Test @RunAsClient
    public void testResourceOwnerPasswordFlow() throws Exception {

        RestAssuredConfig config = newConfig().redirect(redirectConfig().followRedirects(false));

        Response response = given()
               // .log().all()
                .config(config)
                .contentType("application/x-www-form-urlencoded")
                .authentication().preemptive().basic("client", "password")
                .formParam("grant_type", "password")
                .formParam("username", "test")
                .formParam("password", "password")
                .formParam("client_id", "sample")
                .when()
                .post(SampleRequest.TOKEN_ENDPOINT)
                ;


        response.then().statusCode(200);
        System.out.println(response.asString());
        String accessToken = response.jsonPath().getString("access_token");

        SampleRequest.verify(accessToken);
    }
}
