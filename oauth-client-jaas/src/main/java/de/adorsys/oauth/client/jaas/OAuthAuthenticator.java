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
package de.adorsys.oauth.client.jaas;

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
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.Principal;

/**
 * OAuthAuthenticator
 */
@SuppressWarnings({ "UnusedParameters", "unused" })
public class OAuthAuthenticator extends AuthenticatorBase {

	private static final Logger LOG = LoggerFactory.getLogger(OAuthAuthenticator.class);

	private URI authEndpoint;
	private URI tokenEndpoint;
	private URI userInfoEndpoint;

	private boolean supportHttpSession;

	private boolean supportAuthCode;

	private boolean supportGuest;

	private CloseableHttpClient cachingHttpClient;
	private String clientSecretValue;

	private ClientID clientId;

	private ClientSecretBasic clientSecretBasic;

	/**
	 * Initializing
	 */
	public OAuthAuthenticator() {
		// authcode is default enabled
		supportAuthCode = true;
	}

	@Override
	protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig loginConfig) throws IOException {

		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		URI requestURI = null;
		try {
			String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
			requestURI = new URL(request.getScheme(), request.getServerName(), request.getServerPort(), request.getDecodedRequestURI() + query).toURI();
		} catch (Exception e) {
			LOG.error("ups", e);
		}

		LOG.debug("Request " + requestURI);

		// 1. check for token
		AccessToken accessToken = resolveAccessToken(request, requestURI);

		// 1.1 kein accessToken and guest allowed
		if (accessToken == null && supportGuest) {
			principal = context.getRealm().authenticate("guest", "NONE");
			request.setUserPrincipal(principal);
			return true;
		}

		// try to authenticate with accessToken
        if (authenticate(accessToken, request, response)) {
			return true;
		}

		// return 401 if authorization grant flow disallowed
		if (!supportAuthCode) {
			response.setStatus(401);
			return false;
		}

		// 2. check for auth_grant
		AuthorizationCode authorizationCode = resolveAuthorizationCode(request, requestURI);
		if (authorizationCode != null) {
            AccessTokenResponse accessTokenResponse = handleAuthorization(authorizationCode, requestURI, response);
            accessToken = accessTokenResponse != null &&  accessTokenResponse.getTokens() != null ? accessTokenResponse.getTokens().getAccessToken() : null;

            // authenticate and store bearer token in session
            if (accessToken != null && authenticate(accessToken, request, response)) {
                return true;
            }
		}

		// 3. redirect to authEndpoint
		try {
			AuthorizationRequest authorizationRequest = new AuthorizationRequest.Builder(new ResponseType(Value.CODE), clientId).endpointURI(authEndpoint)
					.redirectionURI(requestURI).build();

			String redirect = String.format("%s?%s", authorizationRequest.toHTTPRequest().getURL(), authorizationRequest.toHTTPRequest().getQuery());

			LOG.info("redirect to {}", redirect);

			response.sendRedirect(redirect);

		} catch (Exception e) {
			LOG.error(e.getClass().getSimpleName() + " " + e.getMessage());
			throw new IOException(e);
		}

		return false;
	}

	/**
	 * handleAuthorization - ask tokenEndpoint for access token
	 */
	private AccessTokenResponse  handleAuthorization(AuthorizationCode authorizationCode, URI redirect, HttpServletResponse response) {

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

	/**
	 * resolveAuthorizationCode
	 */
	private AuthorizationCode resolveAuthorizationCode(Request request, URI requestURI) {
		try {
			AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(requestURI);
			return response.getAuthorizationCode();
		} catch (Exception e) {
			LOG.trace("invalid authorization-response {}", requestURI);
		}
		return null;
	}

	/**
	 * resolveAccessToken: auth header and query param supported (form param not supported)
	 */
	private AccessToken resolveAccessToken(Request request, URI requestURI) {
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
	 * authenticate with accessToken
	 */
	@SuppressWarnings("unchecked")
	private boolean authenticate(AccessToken accessToken, Request request, HttpServletResponse response) {

		if (accessToken == null) {
			return false;
		}

		LOG.debug("authenticate accessToken {}", accessToken);
		
		UserInfo userInfo = null;
		try {

			URI uri = new URI(String.format("%s?id=%s", userInfoEndpoint.toString(), accessToken.getValue()));
			HttpGet httpGet = new HttpGet(uri);

			httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());

			HttpCacheContext context = HttpCacheContext.create();
			CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context);
			LOG.debug("read userinfo {} {}", accessToken.getValue(), context.getCacheResponseStatus());

			HttpEntity entity = userInfoResponse.getEntity();
			if (entity==null){
				LOG.info("no userInfo available for {}", accessToken.getValue());
				return false;
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			entity.writeTo(baos);
			userInfo = UserInfo.parse(baos.toString());
		} catch (Exception e) {
			LOG.error("ups", e);
		}

		if (userInfo == null) {
			LOG.trace("no userInfo available for {}", accessToken.getValue());
			return false;
		}

		// use the request to provide userinfo in loginmodules
		request.setAttribute(UserInfo.class.getName(), userInfo);

		Principal principal = context.getRealm().authenticate(userInfo.getSubject().getValue(), accessToken.getValue());
		if (supportHttpSession) {
			request.getSessionInternal(); // force to create http-session
		}
		request.setUserPrincipal(principal);
		response.setHeader("Authorization", accessToken.toAuthorizationHeader());
		register(request, response, principal, "OAUTH", userInfo.getSubject().getValue(), accessToken.getValue());

		return true;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void start() throws LifecycleException {
		if (authEndpoint == null || tokenEndpoint == null || userInfoEndpoint == null || clientId == null) {
			throw new LifecycleException("Endpoint/ClientId missing");
		}

		CacheConfig cacheConfig = CacheConfig.custom().setMaxCacheEntries(1000).setMaxObjectSize(8192).build();

		RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(30000).setSocketTimeout(30000).build();

		cachingHttpClient = CachingHttpClients.custom().setCacheConfig(cacheConfig).setDefaultRequestConfig(requestConfig).build();

		if (clientSecretValue != null) {
			clientSecretBasic = new ClientSecretBasic(clientId, new Secret(clientSecretValue));
		}

		super.start();
		LOG.info("OAuthAuthenticator initialized, authEndpoint={}, tokenEndpoint={}", authEndpoint, tokenEndpoint);
	}

	public void setAuthEndpoint(String authEndpoint) {
		try {
			this.authEndpoint = new URI(authEndpoint);
		} catch (Exception e) {
			throw new IllegalArgumentException("invalid authEndpoint " + authEndpoint);
		}
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		try {
			this.tokenEndpoint = new URI(tokenEndpoint);
		} catch (Exception e) {
			throw new IllegalArgumentException("invalid tokenEndpoint " + tokenEndpoint);
		}
	}

	public void setUserInfoEndpoint(String userInfoEndpoint) {
		try {
			this.userInfoEndpoint = new URI(userInfoEndpoint);
		} catch (Exception e) {
			throw new IllegalArgumentException("invalid userInfoEndpoint " + userInfoEndpoint);
		}
	}

	public void setSupportHttpSession(boolean supportHttpSession) {
		this.supportHttpSession = supportHttpSession;
	}

	public void setSupportAuthCode(boolean supportAuthCode) {
		this.supportAuthCode = supportAuthCode;
	}

    public void setClientSecret(String clientSecret) {
        this.clientSecretValue = clientSecret;
    }

	public void setClientId(String clientId) {
		this.clientId = new ClientID(clientId);
	}

	public void setSupportGuest(boolean supportGuest) {
		this.supportGuest = supportGuest;
	}
}
