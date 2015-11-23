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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.mongodb.client.MongoDatabase;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * TestMongoDbTokenStore
 */
public class TestMongoDbTokenStore {

    private static MdbTokenStore tokenStore;
    private static MongoDatabase mongoDb;
    private static long initialCount;

    private static final boolean EXCLUSIVE = true;

    @BeforeClass
    public static void onBefore() {
        try {
            mongoDb = new MongoDbProvider().producesMongoDatabase();
            initialCount = mongoDb.getCollection(MdbTokenStore.COLLECTION_NAME).count();
            tokenStore = new MdbTokenStore();
            tokenStore.setMongoDb(mongoDb);
        } catch (Exception e) {
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

        Token token = new BearerAccessToken();
        String id = tokenStore.add(token, createUserInfo());
        assertEquals(token.getValue(), id);

        AccessToken accessToken = tokenStore.load(id);
        assertNotNull(accessToken);
        assertEquals(accessToken, token);

        tokenStore.remove(token.getValue());
    }

    @Test
    public void testAuthorizationCode() {
        if (tokenStore == null) {
            return;
        }

        Token token = new BearerAccessToken();
        AuthorizationCode authCode = new AuthorizationCode();

        String id = tokenStore.add(token, createUserInfo(), authCode);
        assertEquals(token.getValue(), id);

        AccessToken accessToken = tokenStore.load(authCode);
        assertNotNull(accessToken);
        assertEquals(accessToken, token);

        tokenStore.remove(token.getValue());
    }

    @Test
    public void testRefreshToken() {
        if (tokenStore == null) {
            return;
        }

        Token token = new RefreshToken();

        String id = tokenStore.add(token, createUserInfo());
        assertEquals(token.getValue(), id);

        RefreshToken refreshToken = tokenStore.loadRefreshToken(id);
        assertNotNull(refreshToken);
        assertEquals(token, refreshToken);

        tokenStore.remove(token.getValue());
    }

    @Test
    public void testUserInfo() {
        if (tokenStore == null) {
            return;
        }

        Token token = new BearerAccessToken();
        UserInfo userInfo = createUserInfo();
        String id = tokenStore.add(token, userInfo);
        assertEquals(token.getValue(), id);

        UserInfo loadedUserInfo = tokenStore.loadUserInfo(token.getValue());
        assertNotNull(loadedUserInfo);
        assertEquals(userInfo.toJSONObject().toJSONString(), loadedUserInfo.toJSONObject().toJSONString());

        tokenStore.remove(token.getValue());
    }

    @Test
    public void testValid() {
        if (tokenStore == null) {
            return;
        }

        Token token = new BearerAccessToken(10, new Scope("scope"));
        String id = tokenStore.add(token, createUserInfo());
        assertEquals(token.getValue(), id);

        assertTrue(tokenStore.isValid(id));
        tokenStore.remove(token.getValue());

        token = new BearerAccessToken(-1, new Scope("scope"));
        id = tokenStore.add(token, createUserInfo());
        assertEquals(token.getValue(), id);
        assertFalse(tokenStore.isValid(id));

        tokenStore.remove(token.getValue());
    }
}
