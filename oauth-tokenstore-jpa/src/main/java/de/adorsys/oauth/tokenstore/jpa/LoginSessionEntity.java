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

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.Table;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

/**
 * LoginSessionEntity
 */

@Entity
@Table(name = "LOGIN_SESSION_ENTITY")
@SuppressWarnings({"FieldCanBeLocal", "unused"})
public class LoginSessionEntity {

    @Id
    @Column(name = "ID")
    private String id;

    @Column(name = "CREATED")
    private Date created;

    @Lob
    @Column(name = "USER_INFO")
    private String userInfo;

    @Column(name = "VALID")
    private Boolean valid;

    public LoginSessionEntity() {
    }

    public LoginSessionEntity(LoginSessionToken token, UserInfo userInfo) {
        this.id    = token.getValue();
        this.userInfo = userInfo.toJSONObject().toJSONString();
        this.valid = true;
    }


    @PrePersist
    public void onPrePersist() {
        if (created == null) {
            created = new Date();
        }
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

    public Boolean getValid() {
        return valid;
    }

    public void setValid(Boolean valid) {
        this.valid = valid;
    }
}
