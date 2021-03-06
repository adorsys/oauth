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
package de.adorsys.oauth.tokenstore.jpa;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.Stateless;
import javax.persistence.Cache;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import java.net.URI;

/**
 * JpaTokenStore
 */
@Stateless
@SuppressWarnings("unused")
public class JpaTokenStore implements TokenStore {

    private static final Logger LOG = LoggerFactory.getLogger(JpaTokenStore.class);
    
    @PersistenceContext(unitName = "oauth")
    private EntityManager entityManager;

    @Override
    public RefreshTokenAndMetadata findRefreshToken(RefreshToken refreshToken) {
        if (refreshToken == null || refreshToken.getValue() == null) {
            return null;
        }

        TokenEntity refreshTokenEntity = entityManager.find(TokenEntity.class, refreshToken.getValue());
        if (refreshTokenEntity != null) {
            return new RefreshTokenAndMetadata(refreshTokenEntity.asRefreshToken(), refreshTokenEntity.getUserInfo(),
                    refreshTokenEntity.getClientId(), refreshTokenEntity.getLoginSessionToken());
        }

        return null;
    }

    @Override
    public void addAuthCode(AuthorizationCode code, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId, URI redirectUri) {
        AuthCodeEntity authCodeEntity = new AuthCodeEntity(code, userInfo, clientId, sessionId, redirectUri);
        entityManager.persist(authCodeEntity);
        entityManager.flush();
    }

    @Override
    public void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId) {
        TokenEntity tokenEntity = new TokenEntity(token, userInfo, clientId, sessionId);
        entityManager.persist(tokenEntity);
    }

    @Override
    public void addRefreshToken(RefreshToken token, UserInfo userInfo, ClientID clientId, LoginSessionToken sessionId, int refreshTokenLifeTime) {
        TokenEntity tokenEntity = new TokenEntity(token, userInfo, clientId, sessionId, refreshTokenLifeTime);
        entityManager.persist(tokenEntity);
    }

    @Override
    public void addAccessToken(BearerAccessToken token, UserInfo userInfo, ClientID clientId, RefreshToken refreshToken) {
        TokenEntity tokenEntity = new TokenEntity(token, userInfo, clientId, null);

        if (refreshToken != null) {
            TokenEntity refreshTokenEntity = entityManager.find(TokenEntity.class, refreshToken.getValue());
            assert refreshTokenEntity != null : "existing refresh token is expected if given as argument";
            tokenEntity.setRefreshToken(refreshTokenEntity);
            tokenEntity.setLoginSession(refreshTokenEntity.getLoginSession());
        }

        entityManager.persist(tokenEntity);
    }

    @Override
    public void remove(String id, ClientID clientId) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        if (tokenEntity == null) {
            LOG.warn("Attempt to delete not existing token: " + id);
            return;
        }

        entityManager.detach(tokenEntity);
        if (clientId != null && !clientId.equals(tokenEntity.getClientId())) {
            LOG.warn("clientIds are different: " + clientId + " vs. " + tokenEntity.getClientId());
        }

        // delete the refresh tokens for this token
        Query queryRefreshToken = entityManager.createNamedQuery(TokenEntity.DELETE_REFRESH_TOKEN_BY_PARENT_ID);
        queryRefreshToken.setParameter("id", id);
        int updateCountRefreshToken = queryRefreshToken.executeUpdate();
        LOG.debug("Removed Refresh-Tokens for parent id {}, count {}", id, updateCountRefreshToken);

        Query q = entityManager.createNamedQuery(TokenEntity.DELETE_TOKEN_BY_ID);
        q.setParameter("id", id);
        int updateCount = q.executeUpdate();
        LOG.debug("Remove Token {}, Count {}", id, updateCount);
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
        return entity.asAccessToken();
    }

    @Override
    public AuthCodeAndMetadata consumeAuthCode(AuthorizationCode authCode) {
        String authCodeId = authCode.getValue();
        AuthCodeEntity authCodeEntity = entityManager.find(AuthCodeEntity.class, authCodeId);

        if (authCodeEntity == null) {
            return null;
        }

        AuthCodeAndMetadata authCodeAndMetadata = new AuthCodeAndMetadata(
                authCodeEntity.getRedirectUri(),
                authCodeEntity.getUserInfo(),
                new ClientID(authCodeEntity.getClientId()),
                authCodeEntity.getLoginSession() != null ? new LoginSessionToken(authCodeEntity.getLoginSession()) : null);

        entityManager.remove(authCodeEntity);

        return authCodeAndMetadata;
    }

    @Override
    public boolean isValid(String id) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        return tokenEntity != null && tokenEntity.isValid();
    }

    @Override
    public void addLoginSession(LoginSessionToken sessionId, UserInfo userInfo) {
        LoginSessionEntity loginSessionEntity = new LoginSessionEntity(sessionId, userInfo);
        entityManager.persist(loginSessionEntity);
    }

    @Override
    public UserInfo loadUserInfoFromLoginSession(LoginSessionToken sessionId) {
        if (sessionId == null) {
            return null;
        }

        LoginSessionEntity loginSessionEntity = entityManager.find(LoginSessionEntity.class, sessionId.getValue());
        if (loginSessionEntity != null) {
            return loginSessionEntity.getUserInfo();
        }
        return null;
    }

    @Override
    public void removeLoginSession(LoginSessionToken sessionId) {
        entityManager.createNamedQuery(LoginSessionEntity.DELETE_LOGIN_SESSION).setParameter("id", sessionId.getValue()).executeUpdate();
    }

    @Override
    public void remove(LoginSessionToken loginSessionToken) {
        Query queryDeleteATokens = entityManager.createNamedQuery(TokenEntity.DELETE_ACCESS_TOKEN_BY_LOGINSESSION);
        queryDeleteATokens.setParameter("loginSession", loginSessionToken.getValue());
        int deletedAccessTokens = queryDeleteATokens.executeUpdate();
        LOG.debug("delete {} access tokens for loginsession", deletedAccessTokens);
        Query queryDeleteRTokens = entityManager.createNamedQuery(TokenEntity.DELETE_REFRESH_TOKEN_BY_LOGINSESSION);
        queryDeleteRTokens.setParameter("loginSession", loginSessionToken.getValue());
        int deletedRefreshTokens = queryDeleteRTokens.executeUpdate();
        LOG.debug("delete {} refresh tokens for loginsession", deletedRefreshTokens);
    }

    @Override
    public boolean isValid(LoginSessionToken loginSessionToken) {
        LoginSessionEntity loginSessionEntity = entityManager.find(LoginSessionEntity.class, loginSessionToken.getValue());

        if (loginSessionEntity == null) {
            return false;
        }

        return loginSessionEntity.getValid();
    }

    @Override
    public void invalidateLoginSession(LoginSessionToken loginSessionToken) {
        LoginSessionEntity loginSessionEntity = entityManager.find(LoginSessionEntity.class, loginSessionToken.getValue());

        if (loginSessionEntity != null) {
            loginSessionEntity.setValid(false);
        }
    }

    @Override
    public UserInfo loadUserInfo(String id) {
        TokenEntity tokenEntity = entityManager.find(TokenEntity.class, id);
        return tokenEntity == null ? null : tokenEntity.getUserInfo();
    }
}
