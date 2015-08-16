package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * TokenStore
 */
public interface TokenStore {

    String add(Token token, UserInfo userInfo);

    String add(Token token, UserInfo userInfo, AuthorizationCode authCode);

    void remove(String id);

    AccessToken load(String id);

    AccessToken load(AuthorizationCode authCode);

    RefreshToken loadRefreshToken(String id);

    UserInfo loadUserInfo(String id);

    boolean isValid(String id);
}
