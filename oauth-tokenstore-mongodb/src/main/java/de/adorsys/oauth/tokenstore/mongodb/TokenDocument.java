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

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.server.LoginSessionToken;

import org.bson.Document;

import java.util.Date;
import java.util.Map;

/**
 * TokenEntity
 */
@SuppressWarnings({"FieldCanBeLocal", "unused"})
public class TokenDocument<T extends Token> {
	
	enum TokenType {
		ACCESS,
		REFRESH
	}
	
	private final T token;
    
    private final TokenType type;

    private final Date created;

    private final Map<String, Object> userInfo;

    private final Date expires;

    private final ClientID clientId;
    
    private final LoginSessionToken sessionId;

    private String refreshTokenRef;
    
    public TokenDocument(T token, Date created, ClientID clientId, LoginSessionToken sessionId, UserInfo userInfo) {
        this(token, created, clientId, sessionId, userInfo, 0);
    }

    public TokenDocument(T token, Date created, ClientID clientId, LoginSessionToken sessionId, UserInfo userInfo, int refreshTokenLifeTime) {
        if (token instanceof BearerAccessToken) {
            this.type = TokenType.ACCESS;
        } else if (token instanceof RefreshToken) {
            this.type = TokenType.REFRESH;
        } else {
            throw new IllegalArgumentException("Unknow token type " + token.getClass().getName());
        }
        this.token = token;
        this.created = created;
        this.sessionId = sessionId;
        this.clientId = clientId;

        if (token instanceof AccessToken && 0 != ((AccessToken) token).getLifetime()) {
            expires = new Date(created.getTime() + ((AccessToken) token).getLifetime() * 1000);
        } else {
            if (refreshTokenLifeTime == 0) {
                expires = new Date(Long.MAX_VALUE);
            } else {
                expires = new Date(created.getTime() + refreshTokenLifeTime * 1000);
            }
        }

        if (userInfo != null) {
            this.userInfo = userInfo.toJSONObject();
        } else {
            this.userInfo = null;
        }
    }

    public Document asDocument() {
        Document document = new Document("_id", token.getValue())
                .append("created", created)
                .append("clientId", clientId.getValue())
                .append("userInfo", userInfo)
                .append("type", type.name());
        if (sessionId != null) {
        	document.append("sessionId", sessionId.getValue());
        }
        
        if (expires != null) {
            document.append("expires", expires);
        }
        if (refreshTokenRef != null) {
            document.append("refreshTokenRef", refreshTokenRef);
        }

        return document;
    }
    

    public static <T extends Token> TokenDocument<T> from(Document document) {
    	String type = document.getString("type");
    	assert type != null : "type is null";
    	
    	TokenDocument<T> tokenDocument;
    	UserInfo userInfoObject = new UserInfo(new JSONObject((Map<String,?>)document.get("userInfo")));
		ClientID clientIdObj = new ClientID(document.getString("clientId"));
		LoginSessionToken loginSession = document.getString("sessionId") != null ? new LoginSessionToken(document.getString("sessionId")) : null;
		Date created = document.getDate("created");
		if (TokenType.ACCESS.name().equals(type)) {
    		long tokenLifetime = (document.getDate("expires").getTime() - created.getTime()) / 1000; 
    		BearerAccessToken bearerAccessToken = new BearerAccessToken(document.getString("_id"), tokenLifetime, null);
			tokenDocument = (TokenDocument<T>) new TokenDocument<BearerAccessToken>(bearerAccessToken, created, clientIdObj, loginSession, userInfoObject);
    	} else if (TokenType.REFRESH.name().equals(type)) {
            int tokenLifetime = 0;
		    if (document.getDate("expires") != null) {
                tokenLifetime = (int) (document.getDate("expires").getTime() - created.getTime()) / 1000;
            }
            RefreshToken refreshToken = new RefreshToken(document.getString("_id"));
			tokenDocument = (TokenDocument<T>) new TokenDocument<RefreshToken>(refreshToken,  created, clientIdObj, loginSession,
                    userInfoObject, tokenLifetime);
    	} else {
    		throw new IllegalArgumentException("unknow token type " + type);
    	}
    	
    	
        tokenDocument.refreshTokenRef = document.getString("refreshTokenRef");
        return tokenDocument;
    }

    public T asToken() {
        return getToken();
    }

    public boolean isValid() {
        return expires == null || System.currentTimeMillis() < expires.getTime();
    }

    @Override
    public String toString() {
        return asDocument().toJson();
    }

    public UserInfo getUserInfo() {
        return userInfo == null ? null : new UserInfo(new JSONObject(userInfo));
    }

	public void setRefreshTokenRef(String refreshTokenRef) {
		this.refreshTokenRef = refreshTokenRef;
	}

	public String getRefreshTokenRef() {
		return refreshTokenRef;
	}

	public T getToken() {
		return token;
	}

	public TokenType getType() {
		return type;
	}

	public Date getCreated() {
		return created;
	}

	public Date getExpires() {
		return expires;
	}

	public ClientID getClientId() {
		return clientId;
	}

	public LoginSessionToken getSessionId() {
		return sessionId;
	}
	
	

}
