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

import org.junit.Test;

/**
 * TestAuth
 */
public class TestAuth  {

    public void testAuthCode() throws Exception {

//        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType(Value.CODE), getClientID())
//                .endpointURI(getAuthEndpoint())
//                .redirectionURI(getRedirect("test"))
//                .build();
//
//        HTTPRequest httpRequest = request.toHTTPRequest();
//        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));
//
//        HTTPResponse response = httpRequest.send();
//
//        response.ensureStatusCode(HTTPResponse.SC_FOUND);
//
//        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(response);
//        assertTrue(authorizationResponse.indicatesSuccess());
//
//        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;
//
//        assertNull(successResponse.getAccessToken());
//        assertNotNull(successResponse.getAuthorizationCode());
//
//        TokenRequest tokenRequest = new TokenRequest(
//                getTokenEndpoint(),
//                getClientID(),
//                new AuthorizationCodeGrant(successResponse.getAuthorizationCode(), getRedirect("test")));
//
//
//        //Client secret
//        HTTPRequest httpRequest2 = tokenRequest.toHTTPRequest();
//        httpRequest2.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));
//
//        //send
//        HTTPResponse tokenResponse = httpRequest2.send();
//        tokenResponse.indicatesSuccess();
//
//        AccessTokenResponse accessTokenResponse = AccessTokenResponse.parse(tokenResponse);
//        assertNotNull(accessTokenResponse.getAccessToken());
//        assertNotNull(accessTokenResponse.getRefreshToken());
//
//        System.out.println("testAuthCode: " + accessTokenResponse.getAccessToken().toJSONString());

    }    
    
    @Test
    public void testAuthImplizit() throws Exception {

//        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType(Value.TOKEN), getClientID())
//                .endpointURI(getAuthEndpoint())
//                .redirectionURI(getRedirect("test"))
//                .build();
//
//        HTTPRequest httpRequest = request.toHTTPRequest();
//        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));
//
//        HTTPResponse response = httpRequest.send();
//
//        response.ensureStatusCode(HTTPResponse.SC_FOUND);
//
//        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(response);
//        assertTrue(authorizationResponse.indicatesSuccess());
//
//        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;
//
//        assertNotNull(successResponse.getAccessToken());
//        assertNull(successResponse.getAuthorizationCode());
//
//
//        System.out.println("testAuthImplizit " + successResponse.getAccessToken().toJSONString());

    }
}