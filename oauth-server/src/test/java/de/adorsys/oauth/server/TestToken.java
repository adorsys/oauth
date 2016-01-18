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
/**
 * TestToken.java
 */
package de.adorsys.oauth.server;

import org.junit.Test;

public class TestToken  {

    @Test
    public void testPasswortGrant() throws Exception {
        //Resource owner credentials
//        TokenRequest tokenRequest = new TokenRequest(
//                getTokenEndpoint(),
//                getClientID(),
//                new ResourceOwnerPasswordCredentialsGrant("resourceowner", new Secret("resourceowner_pw")));
//
//        //Client secret
//        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
//        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));
//
//        //send
//        HTTPResponse tokenResponse = httpRequest.send();
//
//        tokenResponse.indicatesSuccess();
//
//        AccessTokenResponse accessTokenResponse = AccessTokenResponse.parse(tokenResponse);
//        assertNotNull(accessTokenResponse.getAccessToken());
//        assertNotNull(accessTokenResponse.getRefreshToken());
//
//        System.out.println("access token: " + accessTokenResponse.getAccessToken().toJSONString());
//        System.out.println("refresh token: " + accessTokenResponse.getRefreshToken().toJSONString());
    }
}
