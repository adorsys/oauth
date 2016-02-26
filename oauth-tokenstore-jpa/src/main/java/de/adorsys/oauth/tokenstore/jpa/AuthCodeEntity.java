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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import de.adorsys.oauth.server.LoginSessionToken;
import net.minidev.json.JSONObject;

import javax.persistence.*;
import java.net.URI;
import java.util.Calendar;
import java.util.Date;

/**
 * AuthCodeEntity
 */

@Entity
@Table(name = "AUTH_CODE_ENTITY")
@SuppressWarnings({"FieldCanBeLocal", "unused"})
public class AuthCodeEntity {

    @Id
    @Column(name = "ID")
    private String id;

    @Column(name = "CREATED")
    private Date created;

    @Column(name = "EXPIRES")
    private Date expires;

    @Lob
    @Column(name = "USER_INFO")
    private String userInfo;

    @Column(name = "CLIENT_ID")
    private String clientId;

    @Column(name = "LOGIN_SESSION")
    private String loginSession;

    @Lob
    @Column(name = "REDIRECT_URI")
    private String redirectUri;

    public AuthCodeEntity() {
    }

    public AuthCodeEntity(AuthorizationCode code, UserInfo userInfo, ClientID clientId,
                          LoginSessionToken sessionId, URI redirectUri) {
        this.id    = code.getValue();
        if (userInfo != null) {
            this.userInfo = userInfo.toJSONObject().toJSONString();
        }
        this.clientId = clientId.getValue();
        this.loginSession = sessionId.getValue();
        this.redirectUri = redirectUri.toString();
    }

    @PrePersist
    public void onPrePersist() {
        if (created == null) {
            created = new Date();
        }
        if (expires == null) {
            expires = new Date(System.currentTimeMillis() + 60000);
        }
    }

    @Override
    public String toString() {
        return expires != null ? String.format("%1$Td.%1$Tm.%1$Ty-%1$TT.%1$TL %2$s", expires, id) : id;
    }

    private JSONObject getJSONObject(String value) {
        if (value == null) {
            return null;
        }
        try {
            return JSONObjectUtils.parse(value);
        } catch (ParseException e) {
            throw new IllegalStateException("invalid content " + e.getMessage());
        }
    }

    public UserInfo getUserInfo() {
        return userInfo == null ? null : new UserInfo(getJSONObject(userInfo));
    }

    public String getJsonUserInfo() {
        return userInfo;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getId() {
        return id;
    }

    public Date getCreated() {
        return created;
    }

    public Date getExpires() {
        return expires;
    }

    public String getClientId() {
        return clientId;
    }

    public String getLoginSession() {
        return loginSession;
    }
}
