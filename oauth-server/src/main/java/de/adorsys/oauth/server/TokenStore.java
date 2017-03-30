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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.net.URI;

/**
 * TokenStore
 */
public interface TokenStore {
	
	RefreshTokenAndMetadata findRefreshToken(RefreshToken refreshToken);

	void addAuthCode(AuthorizationCode token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId, URI redirectUri);

    void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId);

    void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId, long refreshTokenLifetime);

    void addAccessToken(BearerAccessToken token, UserInfo userInfo, ClientID clientId, RefreshToken refreshToken);
    
    void remove(String id, ClientID clientId);

    AccessToken load(String id);

    AuthCodeAndMetadata consumeAuthCode(AuthorizationCode authCode);
    
    UserInfo loadUserInfo(String id);

    boolean isValid(String id);

    void addLoginSession(LoginSessionToken sessionId, UserInfo userInfo);

    UserInfo loadUserInfoFromLoginSession(LoginSessionToken sessionId);

    void removeLoginSession(LoginSessionToken sessionId);

    void remove(LoginSessionToken loginSessionToken);

    boolean isValid(LoginSessionToken loginSessionToken);

    void invalidateLoginSession(LoginSessionToken loginSessionToken);
}
