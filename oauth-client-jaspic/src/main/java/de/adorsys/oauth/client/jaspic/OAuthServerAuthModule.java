package de.adorsys.oauth.client.jaspic;

import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuthServerAuthModule - SAM
 */
@SuppressWarnings({"unused", "UnusedParameters", "FieldCanBeLocal", "rawtypes", "MismatchedReadAndWriteOfArray", "unchecked"})
public class OAuthServerAuthModule implements ServerAuthModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthServerAuthModule.class);

    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

    private CallbackHandler callbackHandler;

    private URI authEndpoint;
    private URI tokenEndpoint;
    private URI userInfoEndpoint;
    private boolean supportHttpSession;

    private CloseableHttpClient cachingHttpClient;
    private ClientID clientId;


    @Override
    public Class[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES;
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler callbackHandler, Map properties) throws AuthException {
        this.callbackHandler    = callbackHandler;
        this.authEndpoint       = from(properties, "oauth.auth");
        this.tokenEndpoint      = from(properties, "oauth.token");
        this.userInfoEndpoint   = from(properties, "oauth.userinfo");
        this.clientId           = new ClientID((String) properties.get("oauth.clientId"));
        this.supportHttpSession = Boolean.parseBoolean((String) properties.get("oauth.supportHttpSession"));

        CacheConfig cacheConfig = CacheConfig.custom()
                .setMaxCacheEntries(1000)
                .setMaxObjectSize(8192)
                .build();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(30000)
                .setSocketTimeout(30000)
                .build();


        cachingHttpClient = CachingHttpClients.custom()
                .setCacheConfig(cacheConfig)
                .setDefaultRequestConfig(requestConfig)
                .build();

    }

    private URI from(Map properties, String key) throws AuthException {
        String value = (String) properties.get(key);
        if (value == null) {
            throw new AuthException("missing property " + key);
        }
        try {
            return new URL(value).toURI();
        } catch (Exception e) {
            throw new AuthException(String.format("wrong property value %s : %s - %s", key, value, e.getMessage()));
        }
    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject subject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }

    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return AuthStatus.SUCCESS;
        }

        URI requestURI = null;
        try {
            String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
            requestURI = new URL(request.getScheme(), request.getLocalName(), request.getLocalPort(), request.getRequestURI() + query).toURI();
        } catch (Exception e) {
            LOG.error("ups", e);
        }

        LOG.debug("Request " + requestURI);

        // 1. check for token or auth_grant
        AccessToken accessToken = resolveAccessToken(request, requestURI);
        if (accessToken != null && authenticate(accessToken, request, response, clientSubject)) {
            return AuthStatus.SUCCESS;
        }

        // 2. check for auth_grant
        AuthorizationCode authorizationCode = resolveAuthorizationCode(request, requestURI);
        if (authorizationCode != null) {
            return handleAuthorization(authorizationCode, requestURI, response);
        }

        // 3. redirect to authEndpoint
        try {
            AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(new ResponseType(Value.CODE), clientId)
                    .endpointURI(authEndpoint)
                    .redirectionURI(requestURI)
                    .build();

            String redirect = String.format("%s?%s", authorizationRequest.toHTTPRequest().getURL(), authorizationRequest.toHTTPRequest().getQuery());

            LOG.info("redirect to {}", redirect);

            response.sendRedirect(redirect);


        } catch (Exception e) {
            LOG.error(e.getClass().getSimpleName() + " " + e.getMessage());
            throw new AuthException(e.getMessage());
        }

        return AuthStatus.FAILURE;
    }



    /**
     * handleAuthorization - ask tokenEndpoint for access token
     */
    private AuthStatus handleAuthorization(AuthorizationCode authorizationCode, URI redirect, HttpServletResponse response) {

        TokenRequest tokenRequest = new TokenRequest(
                tokenEndpoint,
                clientId,
                new AuthorizationCodeGrant(authorizationCode, redirect));

        try {

            HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();
            tokenResponse.indicatesSuccess();
            AccessTokenResponse accessTokenResponse = AccessTokenResponse.parse(tokenResponse);

            LOG.info("apply accessTokenResponse {}", accessTokenResponse.toJSONObject().toJSONString());
            ServletUtils.applyHTTPResponse(accessTokenResponse.toHTTPResponse(), response);

        } catch (Exception e) {
            LOG.error(e.getClass().getSimpleName() + " " + e.getMessage());
        }

        return AuthStatus.FAILURE;
    }

    /**
     * resolveAuthorizationCode
     */
    private AuthorizationCode resolveAuthorizationCode(HttpServletRequest request, URI requestURI) {
        try {
            AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(requestURI);
            return response.getAuthorizationCode();
        } catch (Exception e) {
            LOG.debug("invalid authorization-response {}", requestURI);
        }
        return null;
    }

    /**
     * resolveAccessToken
     */
    private AccessToken resolveAccessToken(HttpServletRequest request, URI requestURI) {
        try {
            AccessToken accessToken = AuthorizationSuccessResponse.parse(requestURI).getAccessToken();
            if (accessToken != null) {
                return accessToken;
            }
        } catch (Exception e) {
            // LOG.debug("invalid authorization-response {}", requestURI);
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
     * authenticate with accessToken
     */
    private boolean authenticate(AccessToken accessToken, HttpServletRequest request, HttpServletResponse response, Subject clientSubject) throws AuthException {

        LOG.debug("authenticate accessToken {}", accessToken);

        HttpGet httpGet = new HttpGet(userInfoEndpoint);
        httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());

        UserInfo userInfo = null;
        try {
            HttpCacheContext context = HttpCacheContext.create();
            CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context);
            LOG.debug("read userinfo {} {}", accessToken.getValue(), context.getCacheResponseStatus());

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            userInfoResponse.getEntity().writeTo(baos);

            userInfo = UserInfo.parse(baos.toString());
        } catch (Exception e) {
            LOG.error("ups", e);
        }

        if (userInfo == null) {
            LOG.info("no userInfo available for {}", accessToken.getValue());
            return false;
        }

        List<String> groups = (List<String>) userInfo.getClaim("groups");

        if (supportHttpSession) {
            request.getSession(true);
        }

        try {

            String name = userInfo.getName();

            callbackHandler.handle(new Callback[] {
                    new CallerPrincipalCallback(clientSubject, name),
                    new PasswordValidationCallback(clientSubject, name, accessToken.getValue().toCharArray()),
                    new GroupPrincipalCallback(clientSubject, groups.toArray(new String[groups.size()]))
            });

        } catch (IOException | UnsupportedCallbackException e) {
            throw new AuthException(e.getMessage());
        }

        return true;
    }

}
