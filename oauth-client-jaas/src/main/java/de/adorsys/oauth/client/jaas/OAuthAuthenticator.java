package de.adorsys.oauth.client.jaas;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.Principal;

import javax.servlet.http.HttpServletResponse;

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

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

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

    // authcode is default enabled
	private boolean supportAuthCode = true;

	private CloseableHttpClient cachingHttpClient;
	private ClientID clientId;

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

		// 1. check for token or auth_grant
		AccessToken accessToken = resolveAccessToken(request, requestURI);
		if (accessToken == null) {
			principal = context.getRealm().authenticate("guest", "NONE");
			request.setUserPrincipal(principal);
			return true;
		} else if (authenticate(accessToken, request, response)) {
			return true;
		}
		
		if (!supportAuthCode) {
			response.setStatus(401);
			return false;
		}

		// 2. check for auth_grant
		AuthorizationCode authorizationCode = resolveAuthorizationCode(request, requestURI);
		if (authorizationCode != null) {
            AccessTokenResponse accessTokenResponse = handleAuthorization(authorizationCode, requestURI, response);
            accessToken = accessTokenResponse.getAccessToken();

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

		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientId, new AuthorizationCodeGrant(authorizationCode, redirect));

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
			LOG.debug("invalid authorization-response {}", requestURI);
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

		LOG.debug("authenticate accessToken {}", accessToken);
		
		try {
			HttpContext.init(request, response);
			UserInfo userInfo = null;
			try {
	
				URI uri = new URI(String.format("%s?id=%s", userInfoEndpoint.toString(), accessToken.getValue()));
				HttpGet httpGet = new HttpGet(uri);
	
				httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());
	
				HttpCacheContext context = HttpCacheContext.create();
				CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context);
				LOG.debug("read userinfo {} {}", accessToken.getValue(), context.getCacheResponseStatus());
	
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				HttpEntity entity = userInfoResponse.getEntity();
				if(entity==null){
					LOG.info("no userInfo available for {}", accessToken.getValue());
					return false;
				}
				entity.writeTo(baos);
				String userInfoString = baos.toString();
				userInfo = UserInfo.parse(userInfoString);
			} catch (Exception e) {
				LOG.error("ups", e);
			}
	
			if (userInfo == null) {
				LOG.info("no userInfo available for {}", accessToken.getValue());
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
		} finally {
			HttpContext.release();
		}
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

	public void setClientId(String clientId) {
		this.clientId = new ClientID(clientId);
	}

	public void setSupportHttpSession(boolean supportHttpSession) {
		this.supportHttpSession = supportHttpSession;
	}

	public void setSupportAuthCode(boolean supportAuthCode) {
		this.supportAuthCode = supportAuthCode;
	}
}
