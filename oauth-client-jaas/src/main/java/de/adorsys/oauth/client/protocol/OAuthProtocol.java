package de.adorsys.oauth.client.protocol;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;


/**
 * OAuthProtocol
 */
public class OAuthProtocol {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthProtocol.class);

    private URI authEndpoint;
    private URI tokenEndpoint;
    private ClientID clientId;
    private ClientSecretBasic clientSecretBasic;
    private String clientSecretValue;

    public static OAuthProtocol from(Map<String, String> properties) {
        OAuthProtocol oauthProtocol = new OAuthProtocol();
        oauthProtocol.setAuthEndpoint(properties.get("authEndpoint"));
        oauthProtocol.setTokenEndpoint(properties.get("tokenEndpoint"));
        oauthProtocol.setClientId(properties.get("clientId"));
        oauthProtocol.setClientSecretValue(properties.get("clientSecret"));
        return oauthProtocol.initialize();
    }

    /**
     * extractURI
     */
    public URI extractURI(HttpServletRequest request) {
        try {
            String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
            return new URL(request.getScheme(), request.getServerName(), request.getServerPort(), request.getRequestURI() + query).toURI();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * OAuthProtocol builder
     */
    public void setAuthEndpoint(String authEndpoint) {
        try {
            this.authEndpoint = new URI(authEndpoint);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid authEndpoint " + e.getMessage());
        }
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        try {
            this.tokenEndpoint = new URI(tokenEndpoint);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid tokenEndpoint " + e.getMessage());
        }
    }

    public void setClientId(String clientId) {
        this.clientId = new ClientID(clientId);
    }

    public void setClientSecretValue(String clientSecretValue) {
        this.clientSecretValue = clientSecretValue;
    }

    public OAuthProtocol initialize() {
        if (authEndpoint == null || tokenEndpoint == null ||  clientId == null) {
            throw new IllegalStateException("Endpoint/ClientId missing");
        }

        if (clientSecretValue != null) {
            clientSecretBasic = new ClientSecretBasic(clientId, new Secret(clientSecretValue));
        }

        return this;
    }


    /**
     * resolveAccessToken: auth header and query param supported (form param not supported)
     */
    public AccessToken resolveAccessToken(HttpServletRequest request) {
        String queryParam = request.getParameter("access_token");
        if (StringUtils.isNotEmpty(queryParam)) {
            return new BearerAccessToken(queryParam);
        }

        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.contains("Bearer")) {
            try {
                return BearerAccessToken.parse(authorization);
            } catch (Exception e) {
                LOG.debug("invalid authorization-header {}", authorization);
            }
        }

        return null;
    }

    /**
     * check if an authorization code is available and change this code to an access token
     */
    public AccessToken runAuthorizationCodeFlow(URI requestURI) {
        AuthorizationCode authorizationCode = resolveAuthorizationCode(requestURI);
        if (authorizationCode == null) {
            return null;
        }

        AccessTokenResponse accessTokenResponse = handleAuthorization(authorizationCode, requestURI);
        return accessTokenResponse != null &&  accessTokenResponse.getTokens() != null ? accessTokenResponse.getTokens().getAccessToken() : null;
    }

    /**
     * ask the authEndpoint for an authorization code
     */
    public void doAuthorizationRequest(HttpServletResponse response, URI requestURI)  {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(new ResponseType(Value.CODE), clientId).endpointURI(authEndpoint)
                .redirectionURI(requestURI).build();

        String redirect = String.format("%s?%s", authorizationRequest.toHTTPRequest().getURL(), authorizationRequest.toHTTPRequest().getQuery());

        LOG.info("redirect to {}", redirect);

        try {
            response.sendRedirect(redirect);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

    }

    /**
     * parse URI for authorization code
     */
    private AuthorizationCode resolveAuthorizationCode(URI requestURI) {
        try {
            AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(requestURI);
            return response.getAuthorizationCode();
        } catch (Exception e) {
            LOG.trace("invalid authorization-response {}", requestURI);
        }
        return null;
    }

    /**
     * handleAuthorization - ask tokenEndpoint for access token
     */
    private AccessTokenResponse handleAuthorization(AuthorizationCode authorizationCode, URI redirect) {

        TokenRequest tokenRequest = clientSecretBasic == null ?
                new TokenRequest(tokenEndpoint, clientId, new AuthorizationCodeGrant(authorizationCode, redirect))
                : new TokenRequest(tokenEndpoint, clientSecretBasic, new AuthorizationCodeGrant(authorizationCode, redirect));
        try {
            HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();
            tokenResponse.indicatesSuccess();
            return AccessTokenResponse.parse(tokenResponse);
        } catch (Exception e) {
            LOG.error(e.getClass().getSimpleName() + " " + e.getMessage());
        }

        return null;
    }

    @Override
    public String toString() {
        return String.format("authEndpoint=%s tokenEndpoint=%s clientId=%s", authEndpoint, tokenEndpoint, clientId);
    }

}
