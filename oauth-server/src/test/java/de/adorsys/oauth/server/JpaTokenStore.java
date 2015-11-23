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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import javax.ejb.Stateless;
import javax.persistence.Cache;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

/**
 * JpaTokenStore
 */
@Stateless
public class JpaTokenStore implements TokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(JpaTokenStore.class);
    
    @PersistenceContext(unitName = "oauth")
    private EntityManager entityManager;

    @Override
    public String add(Token token, UserInfo userInfo, AuthorizationCode authCode) {
        entityManager.persist(new TokenEntity(token, userInfo, authCode));
        return token.getValue();
    }

    @Override
    public String add(Token token, UserInfo userInfo) {
        entityManager.persist(new TokenEntity(token, userInfo));
        return token.getValue();
    }

    @Override
    public void remove(String id) {
        TokenEntity tokenEntity = entityManager.getReference(TokenEntity.class, id);
        if (tokenEntity != null) {
            entityManager.remove(tokenEntity);
        }
    }

    @Override
    public AccessToken load(String id) {
        if (LOG.isDebugEnabled()) {
            Cache cache = entityManager.getEntityManagerFactory().getCache();
            if (cache.contains(TokenEntity.class, id)) {
                LOG.debug("read token from cache {}", id);
            }
        }
        TokenEntity entity = entityManager.find(TokenEntity.class, id);
        return entity == null ? null : entity.asAccessToken();
    }

    @Override
    public AccessToken load(AuthorizationCode authCode) {
        TypedQuery<TokenEntity> query = entityManager.createNamedQuery(TokenEntity.FIND_ACCESSTOKEN, TokenEntity.class);
        query.setParameter(1, authCode.getValue());
        try {
            TokenEntity entity = query.getSingleResult();
            return entity == null ? null : entity.asAccessToken();
        } catch (Exception e) {
            LOG.error("no token available for {}", authCode.getValue());
        }
        return null;
    }

    @Override
    public RefreshToken loadRefreshToken(String id) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        return tokenEntity == null ? null : tokenEntity.asRefreshToken();
    }

    @Override
    public boolean isValid(String id) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        return tokenEntity != null && tokenEntity.isValid();
    }

    @Override
    public UserInfo loadUserInfo(String id) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        return tokenEntity == null ? null : tokenEntity.getUserInfo();
    }
}
