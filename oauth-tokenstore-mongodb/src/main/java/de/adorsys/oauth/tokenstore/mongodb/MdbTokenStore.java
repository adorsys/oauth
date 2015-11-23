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

import de.adorsys.oauth.server.TokenStore;

import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mongodb.client.MongoDatabase;
import com.mongodb.client.result.DeleteResult;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import javax.ejb.Stateless;
import javax.inject.Inject;

/**
 * MdbTokenStore
 */
@Stateless
@SuppressWarnings("unused")
public class MdbTokenStore implements TokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(MdbTokenStore.class);
    
    static final String COLLECTION_NAME = System.getProperty("oauth.mongodb.collection", "tokenstore");
    
    @Inject
    private MongoDatabase mongoDb;

    @Override
    public String add(Token token, UserInfo userInfo, AuthorizationCode authCode) {
        Document document = new TokenDocument(token, userInfo, authCode).asDocument();
        mongoDb.getCollection(COLLECTION_NAME).insertOne(document);
        return token.getValue();
    }

    @Override
    public String add(Token token, UserInfo userInfo) {
        Document document = new TokenDocument(token, userInfo).asDocument();
        mongoDb.getCollection(COLLECTION_NAME).insertOne(document);
        return token.getValue();
    }

    @Override
    public void remove(String id) {
        DeleteResult result = mongoDb.getCollection(COLLECTION_NAME).deleteOne(new Document().append("_id", id));
        LOG.debug("delete {} : {} documents", id, result.getDeletedCount());
    }

    @Override
    public AccessToken load(String id) {
        Document document = mongoDb.getCollection(COLLECTION_NAME).find(new Document().append("_id", id)).first();
        return document == null ? null : TokenDocument.from(document).asAccessToken();
    }

    @Override
    public AccessToken load(AuthorizationCode authCode) {
        Document document = mongoDb.getCollection(COLLECTION_NAME).find(new Document().append("authCode", authCode.getValue())).first();
        return document == null ? null : TokenDocument.from(document).asAccessToken();
    }

    @Override
    public RefreshToken loadRefreshToken(String id) {
        Document document = mongoDb.getCollection(COLLECTION_NAME).find(new Document().append("_id", id)).first();
        return document == null ? null : TokenDocument.from(document).asRefreshToken();
    }

    @Override
    public boolean isValid(String id) {
        Document document = mongoDb.getCollection(COLLECTION_NAME).find(new Document().append("_id", id)).first();
        return document != null && TokenDocument.from(document).isValid();
    }

    @Override
    public UserInfo loadUserInfo(String id) {
        Document document = mongoDb.getCollection(COLLECTION_NAME).find(new Document().append("_id", id)).first();
        return document == null ? null : TokenDocument.from(document).getUserInfo();
    }

    void setMongoDb(MongoDatabase mongoDb) {
        this.mongoDb = mongoDb;
    }

}
