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

import java.util.UUID;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ExtractableResponse;
import com.jayway.restassured.response.Response;
/**
 * TestImplicitFlow
 */
@RunWith(Arquillian.class)
public class TestImplicitFlow {


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
    public void testImplicit() throws Exception {
        String generatedState = UUID.randomUUID().toString();
		ExtractableResponse<Response> response = given()
                .redirects().follow(false)
                .queryParam("response_type", "token")
                .queryParam("client_id", "sample")
                .queryParam("state", generatedState)
                .queryParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .formParam("j_username", "jduke")
        		.formParam("j_password", "1234")
                .when()
                .post(SampleRequest.AUTH_ENDPOINT)
                .then()
                .statusCode(302)
                .extract();
        String location = response.header("Location");
        System.out.println("\nredirect " + location);
        int startIndexAccessToken = location.indexOf("access_token") + 13;
		int endIndexAccessToken = location.indexOf("&", startIndexAccessToken);
		String accessToken = location.substring(startIndexAccessToken, endIndexAccessToken == -1 ? location.length() : endIndexAccessToken);
        
        int beginIndex = location.indexOf("state") + 6;
		String state = location.substring(beginIndex, beginIndex + generatedState.length());
		System.out.println("\noauth token " + accessToken);
		Assert.assertEquals(generatedState, state);
        SampleRequest.verify(accessToken);
    }
}
