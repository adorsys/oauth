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
package de.adorsys.oauth.client.jaspic;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * TestServlet
 */
@RunWith(Arquillian.class)
public class TestJaspic {

    @Deployment
    public static Archive createDeployment() {

        File[] dependencies = Maven.configureResolver().workOffline(true).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve().withTransitivity().asFile();

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(true, "de.adorsys.oauth.client.jaspic")
                .addAsLibraries(dependencies)
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
                .addAsWebInfResource("web.xml")
                ;
    }

    @Test @RunAsClient
    public void testServlet() throws Exception {

        URL url = new URL("http://localhost:8280/sample/hello");

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        int statusCode = connection.getResponseCode();

        if (statusCode == 401) {
            System.out.println("Login required from " + connection.getURL());
            connection = (HttpURLConnection) connection.getURL().openConnection();
            connection.setRequestProperty("Authorization", "Basic dGVzdDoxMjM0NTY=");
            statusCode = connection.getResponseCode();
        }

        if (statusCode != 200) {
            System.out.println("Status " + statusCode);
            return;
        }
        
        String json = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
        AccessTokenResponse tokenResponse = AccessTokenResponse.parse(JSONObjectUtils.parse(json));
        System.out.println("access-token  : " + tokenResponse.getAccessToken());
        System.out.println("lifetime      : " + tokenResponse.getAccessToken().getLifetime());
        System.out.println("refresh-token : " + tokenResponse.getRefreshToken());


        connection = (HttpURLConnection) url.openConnection();
        connection.setRequestProperty("Authorization", "Bearer " + tokenResponse.getAccessToken());
        statusCode = connection.getResponseCode();

        if (statusCode != 200) {
            System.out.println("Status " + statusCode);
            return;
        }

        String cookie = connection.getHeaderField("Cookie");
        if (cookie == null) {
            cookie = connection.getHeaderField("Set-Cookie");
            int idx = cookie != null ? cookie.indexOf(";") : -1;
            if (0 < idx) {
                cookie = cookie.substring(0, idx);
            }
        }

        String content = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
        System.out.println(content);

        if (cookie == null) {
            System.out.println("no http session support");
            return;
        }

        System.out.println("Cookie " + cookie);
        
        // again with cookie
        connection = (HttpURLConnection) url.openConnection();
        connection.setRequestProperty("Cookie", cookie);

        statusCode = connection.getResponseCode();
        if (statusCode != 200) {
            System.out.println("Status " + statusCode);
            return;
        }
        content = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
        System.out.println(content);

    }
}
