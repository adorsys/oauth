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

import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.result.DeleteResult;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.server.AuthCodeAndMetadata;
import de.adorsys.oauth.server.LoginSessionToken;
import de.adorsys.oauth.server.RefreshTokenAndMetadata;
import de.adorsys.oauth.server.TokenStore;

import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;

import java.net.URI;
import java.util.Date;
import java.util.Map;

import net.minidev.json.JSONObject;

/**
 * MdbTokenStore
 */
@Singleton
@SuppressWarnings({"unchecked"})
public class MdbTokenStore implements TokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(MdbTokenStore.class);
    
    static final String COLLECTION_NAME = System.getProperty("oauth.mongodb.collection", "tokenstore");
    
    @Inject
    private MongoDatabase mongoDb;

	private MongoCollection<Document> collection;

	private MongoCollection<Document> authCodeCollection;

    private MongoCollection<Document> loginSessionCollection;
    
    @PostConstruct
    void initCollection() {
    	collection = mongoDb.getCollection(COLLECTION_NAME);
    	authCodeCollection = mongoDb.getCollection("authCode");
        loginSessionCollection = mongoDb.getCollection("loginSession");
	}
    
	@Override
	public void addAuthCode(AuthorizationCode code, UserInfo userInfo, ClientID clientId,
			LoginSessionToken sessionId, URI redirectUri) {
		Document document = new Document("_id", code.getValue())
				.append("created", new Date())
				.append("expires", new Date(System.currentTimeMillis() + 60000))
				.append("userInfo", userInfo.toJSONObject())
				.append("clientId", clientId.getValue())
				.append("loginSession", sessionId.getValue())
				.append("redirectUri", redirectUri.toString());
		authCodeCollection.insertOne(document);
	}

    
	@Override
	public void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId) {
		TokenDocument<RefreshToken> tokenDocument = new TokenDocument<RefreshToken>(token, new Date(), clientId, sessionId, userInfo);
		Document document = tokenDocument.asDocument();
        collection.insertOne(document);
	}

    @Override
    public void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId, long refreshLifeTime) {
        TokenDocument<RefreshToken> tokenDocument = new TokenDocument<RefreshToken>(token, new Date(), clientId, sessionId,
                userInfo, refreshLifeTime);
        Document document = tokenDocument.asDocument();
        collection.insertOne(document);
    }

	@Override
	public void addAccessToken(BearerAccessToken token, UserInfo userInfo, ClientID clientId, RefreshToken refreshToken) {
		TokenDocument<BearerAccessToken> tokenDocument = new TokenDocument<BearerAccessToken>(token, new Date(), clientId, null, userInfo);
		if (refreshToken != null) {
			tokenDocument.setRefreshTokenRef(refreshToken.getValue());
		}
		Document document = tokenDocument.asDocument();
        collection.insertOne(document);
	}


    @Override
    public void remove(String id, ClientID clientId) {
        Document query = new Document("_id", id);
        Document refreshQuery = new Document("refreshTokenRef", id);
        if (clientId != null) {
            query.append("clientId", clientId.getValue());
            refreshQuery.append("clientId", clientId.getValue());
        }
        DeleteResult result = collection.deleteOne(query);
        LOG.debug("delete {} : {} tokens", id, result.getDeletedCount());
        result = collection.deleteMany(refreshQuery);
        LOG.debug("delete {} : {} access tokens", id, result.getDeletedCount());
    }

    @Override
    public AccessToken load(String id) {
        Document document = collection.find(new Document().append("_id", id)).first();
        return document == null ? null : (AccessToken) TokenDocument.from(document).getToken();
    }

    @Override
    public boolean isValid(String id) {
        Document document = collection.find(new Document().append("_id", id)).first();
        return document != null && TokenDocument.from(document).isValid();
    }

    @Override
    public void addLoginSession(LoginSessionToken sessionId, UserInfo userInfo) {
        Document document = new Document("_id", sessionId.getValue())
                .append("created", new Date())
                .append("userInfo", userInfo.toJSONObject())
                .append("valid", Boolean.TRUE);
        loginSessionCollection.insertOne(document);
    }

    @Override
    public UserInfo loadUserInfoFromLoginSession(LoginSessionToken sessionId) {
        Document document = loginSessionCollection.find(new Document().append("_id", sessionId.getValue())).first();
        if (document == null) {
            return null;
        }
        return new UserInfo(new JSONObject((Map<String, ?>) document.get("userInfo")));
    }

    @Override
    public void removeLoginSession(LoginSessionToken sessionId) {
        DeleteResult result = loginSessionCollection.deleteOne(new Document().append("_id", sessionId.getValue()));
        LOG.debug("delete {} : {} session", sessionId.getValue(), result.getDeletedCount());
    }

    @Override
    public void remove(LoginSessionToken loginSessionToken) {
        FindIterable<Document> refreshTokens = collection.find(new Document("sessionId", loginSessionToken.getValue()));
        for (Document refreshToken : refreshTokens) {
            String refreshTokenId = refreshToken.getString("_id");
            DeleteResult result = collection.deleteMany(new Document("refreshTokenRef", refreshTokenId));
            LOG.debug("delete login session {} : {} access tokens", loginSessionToken.getValue(), result.getDeletedCount());
        }
        DeleteResult result2 = collection.deleteMany(new Document("sessionId", loginSessionToken.getValue()));
        LOG.debug("delete login session {} : {} refresh tokens", loginSessionToken.getValue(), result2.getDeletedCount());
    }

    @Override
    public boolean isValid(LoginSessionToken loginSessionToken) {
        Document document = loginSessionCollection.find(new Document().append("_id", loginSessionToken.getValue())).first();
        if (document == null) {
            return false;
        }
        return document.getBoolean("valid") != null ? document.getBoolean("valid") : false;
    }

    @Override
    public void invalidateLoginSession(LoginSessionToken loginSessionToken) {
        loginSessionCollection.updateOne(new Document().append("_id", loginSessionToken.getValue()),
                new Document("$set", new Document("valid", Boolean.FALSE)));
    }

    @Override
    public UserInfo loadUserInfo(String id) {
        Document document = collection.find(new Document().append("_id", id)).first();
        return document == null ? null : TokenDocument.from(document).getUserInfo();
    }

    void setMongoDb(MongoDatabase mongoDb) {
        this.mongoDb = mongoDb;
    }

	@Override
	public AuthCodeAndMetadata consumeAuthCode(AuthorizationCode authCode) {
		Document document = authCodeCollection.findOneAndDelete(new Document("_id", authCode.getValue()));
		if (document == null) {
			return null;
		}

        String loginSession = document.getString("loginSession");

		return new AuthCodeAndMetadata(
				document.getString("redirectUri"), 
				new UserInfo(new JSONObject((Map<String, ?>) document.get("userInfo"))),
				new ClientID(document.getString("clientId")),
                loginSession != null ? new LoginSessionToken(loginSession) : null);
	}

	@Override
	public RefreshTokenAndMetadata findRefreshToken(RefreshToken refreshToken) {
		Document document = collection.find(new Document("_id", refreshToken.getValue())).first();
		if (document != null) {
			TokenDocument<RefreshToken> tokenDoc = TokenDocument.from(document);
			return new RefreshTokenAndMetadata(tokenDoc.getToken(), tokenDoc.getUserInfo(), tokenDoc.getClientId(), tokenDoc.getSessionId());
		}
		return null;
	}

}
