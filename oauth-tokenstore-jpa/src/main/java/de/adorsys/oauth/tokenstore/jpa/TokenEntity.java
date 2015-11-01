package de.adorsys.oauth.tokenstore.jpa;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.util.Calendar;
import java.util.Date;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.PrePersist;
import javax.persistence.Table;

/**
 * TokenEntity
 */

@Entity
@Table(name = "TOKEN_ENTITY")
@NamedQueries({
    @NamedQuery(name = TokenEntity.FIND_ACCESSTOKEN, query = "select t from TokenEntity t where authCode = ?1")
})
@SuppressWarnings({"FieldCanBeLocal", "unused"})
public class TokenEntity {
    
    static final String FIND_ACCESSTOKEN = "FIND_ACCESSTOKEN";

    @Id
    @Column(name = "ID")
    private String id;
    
    @Column(name = "CREATED")
    private Date created;

    @Column(name = "TOKEN")
    private String token;

    @Column(name = "USER_INFO", length = 10000)
    private String userInfo;

    @Column(name = "EXPIRES")
    private Date expires;

    @Column(name = "AUTH_CODE")
    private String authCode;

    public TokenEntity() {
    }

    public TokenEntity(Token token, UserInfo userInfo) {
        this.id    = token.getValue();
        this.token = token.toJSONObject().toJSONString();

        if (token instanceof AccessToken && 0 != ((AccessToken) token).getLifetime()) {
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.SECOND, (int) ((AccessToken) token).getLifetime());
            expires = cal.getTime();
        }

        if (userInfo != null) {
            this.userInfo = userInfo.toJSONObject().toJSONString();
        }
    }

    public TokenEntity(Token token, UserInfo userInfo, AuthorizationCode authCode) {
        this(token, userInfo);
        this.authCode = authCode != null ? authCode.getValue() : null;
    }

    @PrePersist
    public void onPrePersist() {
        if (created == null) {
            created = new Date();
        }
    }

    public AccessToken asAccessToken() {
        try {
            return BearerAccessToken.parse(getJSONObject(token));
        } catch (Exception e) {
            // 
        }
        return null;
    }

    public RefreshToken asRefreshToken() {
        try {
            return RefreshToken.parse(getJSONObject(token));
        } catch (Exception e) {
            // 
        }
        return null;
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
    
    public boolean isValid() {
        
        AccessToken accessToken = asAccessToken();
        if (accessToken != null) {
            return expires == null || System.currentTimeMillis() < expires.getTime();
        } 
        
        return asRefreshToken() != null;
    }

    @Override
    public String toString() {
        return expires != null ? String.format("%1$Td.%1$Tm.%1$Ty-%1$TT.%1$TL %2$s", expires, token) : token;
    }

    public UserInfo getUserInfo() {
        return userInfo == null ? null : new UserInfo(getJSONObject(userInfo));
    }

    public String getJsonUserInfo() {
        return userInfo;
    }

    public String getAuthCode() {
        return authCode;
    }
}
