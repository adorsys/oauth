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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.jayway.restassured.RestAssured.given;
import static com.jayway.restassured.config.RedirectConfig.redirectConfig;
import static com.jayway.restassured.config.RestAssuredConfig.newConfig;
import static org.junit.Assert.assertTrue;

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
                ;
    }

    @Test @RunAsClient
    public void testImplicit() throws Exception {

        RestAssuredConfig config = newConfig().redirect(redirectConfig().followRedirects(false));

        Response response = given()
                .config(config)
                .queryParam("response_type", "token")
                .queryParam("client_id", "sampe")
                .queryParam("redirect_uri", SampleRequest.SAMPLE_URL)
                .auth().preemptive().basic("test", "1234")
                .when()
                .get(SampleRequest.AUTH_ENDPOINT);

        response.then().statusCode(302);
        String location = response.then().extract().header("Location");

        Pattern pattern = Pattern.compile("[\\?#]([^&=]+)=([^&=]+)");
        Matcher matcher = pattern.matcher(location);

        assertTrue(matcher.find());
        String accessToken = matcher.group(2);

        System.out.println("\noauth token " + accessToken);

        SampleRequest.verify(accessToken);
    }
}
