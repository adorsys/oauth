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
package de.adorsys.oauth.server;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.client.cache.CacheResponseStatus;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.BeforeClass;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * TestUserInfo
 */
public class TestUserInfo extends ArquillianBase {

    @Deployment
    public static Archive createDeployment() {
        return createTestWar();
    }

    @BeforeClass
    public static void beforeClass() {
        HttpURLConnection.setFollowRedirects(false);
    }


    @Test @RunAsClient
    public void testUserInfo() throws Exception {

        String token = login();

        CacheConfig cacheConfig = CacheConfig.custom()
                .setMaxCacheEntries(1000)
                .setMaxObjectSize(8192)
                .build();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(30000)
                .setSocketTimeout(30000)
                .build();

        CloseableHttpClient cachingClient = CachingHttpClients.custom()
                .setCacheConfig(cacheConfig)
                .setDefaultRequestConfig(requestConfig)
                .build();

        HttpCacheContext context = HttpCacheContext.create();
        HttpGet httpGet = new HttpGet(getUserInfoEndpoint());
        httpGet.setHeader("Authorization", new BearerAccessToken(token).toAuthorizationHeader());

        CloseableHttpResponse response = cachingClient.execute(httpGet, context);
        assertEquals(200, response.getStatusLine().getStatusCode());

//        for (Header header : response.getAllHeaders()) {
//            System.out.println(header);
//        }

        String userInfo = readContent(response.getEntity());
        assertNotNull(userInfo);

        CacheResponseStatus responseStatus = context.getCacheResponseStatus();
        System.out.println(responseStatus);
        assertEquals(CacheResponseStatus.CACHE_MISS, responseStatus);
        cachingClient.execute(httpGet, context);
        responseStatus = context.getCacheResponseStatus();
        System.out.println(responseStatus);
        assertEquals(CacheResponseStatus.CACHE_HIT, responseStatus);

    }

    private String login() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType(Value.TOKEN), getClientID())
                .endpointURI(getAuthEndpoint())
                .redirectionURI(getRedirect("test"))
                .build();

        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));

        HTTPResponse response = httpRequest.send();

        response.ensureStatusCode(HTTPResponse.SC_FOUND);

        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(response);
        assertTrue(authorizationResponse.indicatesSuccess());

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;

        assertNotNull(successResponse.getAccessToken());
        assertNull(successResponse.getAuthorizationCode());

        System.out.println("token: " + successResponse.getAccessToken().toJSONString());

        return successResponse.getAccessToken().getValue();
    }

    private String readContent(HttpEntity entity) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        entity.writeTo(baos);
        return baos.toString();

    }
}