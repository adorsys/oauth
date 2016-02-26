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
package de.adorsys.oauth.tokenstore.mongodb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.fakemongo.Fongo;
import com.mongodb.client.MongoDatabase;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.server.LoginSessionToken;
import de.adorsys.oauth.server.RefreshTokenAndMetadata;
import de.adorsys.oauth.server.AuthCodeAndMetadata;

/**
 * TestMongoDbTokenStore
 */
public class TestMongoDbTokenStore {

    private static final LoginSessionToken SESSION_ID = new LoginSessionToken("SESSIONID");
	private static final ClientID CLIENT_ID = new ClientID("CLIENTID");
	private static MdbTokenStore tokenStore;
    private static MongoDatabase mongoDb;
    private static long initialCount;

    private static final boolean EXCLUSIVE = true;

    @BeforeClass
    public static void onBefore() {
        try {
        	Fongo fongo = new Fongo("mongo server 1");
            mongoDb = fongo.getDatabase("testdb");
            initialCount = mongoDb.getCollection(MdbTokenStore.COLLECTION_NAME).count();
            tokenStore = new MdbTokenStore();
            tokenStore.setMongoDb(mongoDb);
            tokenStore.initCollection();
        } catch (Exception e) {
        	e.printStackTrace();
            System.out.println("MongoDB not available, tests disabled");
        }
    }

    @SuppressWarnings("PointlessBooleanExpression")
    @AfterClass
    public static void onAfter() {
        if (tokenStore == null) {
            return;
        }

        if (!EXCLUSIVE) {
            return;
        }

        long count = mongoDb.getCollection(MdbTokenStore.COLLECTION_NAME).count();
        if (initialCount != count) {
            fail(String.format("initial %1d, current %2d", initialCount, count));
        }
    }

    private UserInfo createUserInfo() {
        UserInfo userInfo = new UserInfo(new Subject("test"));
        userInfo.setClaim("groups", Arrays.asList("admin", "oauth"));
        return userInfo;
    }

    @Test
    public void testAccessToken() {
        if (tokenStore == null) {
            return;
        }

        BearerAccessToken token = new BearerAccessToken();
        tokenStore.addAccessToken(token, createUserInfo(), CLIENT_ID, null);
        assertEquals(token.getValue(), token.getValue());

        AccessToken accessToken = tokenStore.load(token.getValue());
        assertNotNull(accessToken);
        assertEquals(accessToken, token);

        tokenStore.remove(token.getValue(), CLIENT_ID);
    }

    @Test
    public void testAuthorizationCode() throws URISyntaxException {
        if (tokenStore == null) {
            return;
        }

        AuthorizationCode authCode = new AuthorizationCode();

        UserInfo createUserInfo = createUserInfo();

		LoginSessionToken sessionId = new LoginSessionToken();
		
		URI redirectUri = new URI("http://acme.org/");
		tokenStore.addAuthCode(authCode, createUserInfo, CLIENT_ID, sessionId, redirectUri);

        AuthCodeAndMetadata refreshTokenAndMetadata = tokenStore.consumeAuthCode(authCode);
        assertNotNull(refreshTokenAndMetadata);
        assertEquals(refreshTokenAndMetadata.getRedirectURI(), redirectUri.toString());
        assertEquals(refreshTokenAndMetadata.getLoginSession(), sessionId);
        assertEquals(refreshTokenAndMetadata.getClientId(), CLIENT_ID);
        assertEquals(refreshTokenAndMetadata.getUserInfo().toJSONObject(), createUserInfo.toJSONObject());

        AuthCodeAndMetadata consumeAuthCode = tokenStore.consumeAuthCode(authCode);
        Assert.assertNull(consumeAuthCode);
    }
    
//    @Test
//    public void testFindRefreshTokenByLoginSession() {
//    	RefreshToken token = new RefreshToken();
//		LoginSessionToken sessionId = new LoginSessionToken();
//		tokenStore.addRefreshToken(token, createUserInfo(), CLIENT_ID, sessionId);
//
//		RefreshToken findRefreshToken = tokenStore.findRefreshToken(sessionId);
//		Assert.assertThat(findRefreshToken, Matchers.notNullValue());
//		tokenStore.remove(findRefreshToken.getValue(), CLIENT_ID);
//
//    }
    
    @Test
    public void testFindRefreshTokenMetadata() {
    	RefreshToken token = new RefreshToken();
		LoginSessionToken sessionId = new LoginSessionToken();
		UserInfo userInfo = createUserInfo();
		tokenStore.addRefreshToken(token, userInfo, CLIENT_ID, sessionId);
		
		RefreshTokenAndMetadata findRefreshToken = tokenStore.findRefreshToken(token);
		Assert.assertThat(findRefreshToken, Matchers.notNullValue());
		Assert.assertThat(findRefreshToken.getClientId(), Matchers.equalTo(CLIENT_ID));
		Assert.assertThat(findRefreshToken.getLoginSession(), Matchers.equalTo(sessionId));
		Assert.assertThat(findRefreshToken.getRefreshToken(), Matchers.equalTo(token));
		Assert.assertThat(findRefreshToken.getUserInfo().toJSONObject(), Matchers.equalTo(userInfo.toJSONObject()));
		tokenStore.remove(findRefreshToken.getRefreshToken().getValue(), CLIENT_ID);
    }

    @Test
    public void testUserInfo() {
        if (tokenStore == null) {
            return;
        }

        BearerAccessToken token = new BearerAccessToken();
        UserInfo userInfo = createUserInfo();
        tokenStore.addAccessToken(token, userInfo, CLIENT_ID, null);

        UserInfo loadedUserInfo = tokenStore.loadUserInfo(token.getValue());
        assertNotNull(loadedUserInfo);
        assertEquals(userInfo.toJSONObject().toJSONString(), loadedUserInfo.toJSONObject().toJSONString());

        tokenStore.remove(token.getValue(), CLIENT_ID);
    }

    @Test
    public void testValid() {
        if (tokenStore == null) {
            return;
        }

        BearerAccessToken token = new BearerAccessToken(10, new Scope("scope"));
        tokenStore.addAccessToken(token, createUserInfo(), CLIENT_ID, null);

        assertTrue(tokenStore.isValid(token.getValue()));
        tokenStore.remove(token.getValue(), CLIENT_ID);

        token = new BearerAccessToken(-1, new Scope("scope"));
        tokenStore.addAccessToken(token, createUserInfo(), CLIENT_ID, null);
        assertFalse(tokenStore.isValid(token.getValue()));

        tokenStore.remove(token.getValue(), CLIENT_ID);
    }
}
