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
package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


/**
 * AuthzResource
 */
@SuppressWarnings("unused")
@WebServlet("/api/auth")
@ApplicationScoped
public class AuthResource extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);

    private static final String CLIENT_ID_STR = "client_id";

    @Inject
    private UserInfoFactory userInfoFactory;

    @Inject
    private TokenStore tokenStore;

    private long tokenLifetime;
    
    @Override
    public void init(ServletConfig config) throws ServletException {
    	try {
    		tokenLifetime = Long.valueOf(config.getServletContext().getInitParameter("lifetime"));
    	} catch (Exception e) {
    		tokenLifetime = 8 * 3600;
    	}
    	
    	LOG.info("token lifetime {}", tokenLifetime);
    }
    
    @Override
    protected void doPost(HttpServletRequest servletRequest, HttpServletResponse resp) throws ServletException, IOException {

        authorize(servletRequest, resp);
    }

	private void authorize(HttpServletRequest servletRequest, HttpServletResponse resp) throws IOException {
		AuthorizationRequest request;
		try {
			request = resolveAuthorizationRequest(servletRequest);
		} catch (ParseException e) {
			ServletUtils.applyHTTPResponse(
                    new TokenErrorResponse(OAuth2Error.INVALID_REQUEST).toHTTPResponse(), resp);
			return;
		}

        
        URI redirectionURI = request.getRedirectionURI();
        if (redirectionURI == null) {
        	ServletUtils.applyHTTPResponse(new AuthorizationErrorResponse(request.getEndpointURI(), OAuth2Error.INVALID_REQUEST, request.getState(), request.getResponseMode()).toHTTPResponse(), resp);
        	return;
        }

        if (servletRequest.getUserPrincipal() == null) {
        	ServletUtils.applyHTTPResponse(
                    new AuthorizationErrorResponse(redirectionURI, OAuth2Error.UNAUTHORIZED_CLIENT, request.getState(), request.getResponseMode()).toHTTPResponse(), resp);
        	return;
        }

        if (request.getClientID() == null) {
        	ServletUtils.applyHTTPResponse(
                    new AuthorizationErrorResponse(redirectionURI, OAuth2Error.INVALID_CLIENT, request.getState(), request.getResponseMode()).toHTTPResponse(), resp);
        }

        if (request.getResponseType() == null) {
        	ServletUtils.applyHTTPResponse(
                    new AuthorizationErrorResponse(redirectionURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, request.getState(), request.getResponseMode()).toHTTPResponse(), resp);
        }

        LoginSessionToken loginSession = (LoginSessionToken) servletRequest.getAttribute("loginSession");
		// rememberme cookie exists and login session invalid => destroy
		if (loginSession != null //
				&& RememberMeCookieUtil.getCookieToken(servletRequest, request.getClientID()) != null //
				&& !tokenStore.isValid(loginSession)) {
			servletRequest.removeAttribute("loginSession");
			tokenStore.removeLoginSession(loginSession);
			HTTPResponse httpResponse = new HTTPResponse(303);
			httpResponse.setLocation(request.toURI());
			ServletUtils.applyHTTPResponse(httpResponse, resp);
			return;
		}

		UserInfo userInfo;
        if (loginSession != null) {
        	userInfo = tokenStore.loadUserInfoFromLoginSession(loginSession);
        	if (userInfo == null) {
        		userInfo = userInfoFactory.createUserInfo(servletRequest);
       			tokenStore.addLoginSession(loginSession, userInfo);
        	}
        } else {
    		userInfo = userInfoFactory.createUserInfo(servletRequest);
        }

        LOG.debug(userInfo.toJSONObject().toJSONString());
        
        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());
		
		HTTPResponse response;
		if (request.getResponseType().impliesCodeFlow()) {
        	AuthorizationCode authCode = new AuthorizationCode();
            LOG.debug("impliesCodeFlow {}", authCode.toJSONString());
			tokenStore.addAuthCode(authCode, userInfo, request.getClientID(), loginSession, redirectionURI);

			response = new AuthorizationSuccessResponse(redirectionURI, authCode, null, request.getState(), request.getResponseMode()).toHTTPResponse();

        } else {

            LOG.debug("impliesTokenFlow {}", accessToken.toJSONString());
            tokenStore.addAccessToken(accessToken, userInfo, request.getClientID(), null);
            
            URI cleanUrl = getCleanUrl(redirectionURI);
            response = new AuthorizationSuccessResponse(cleanUrl, null, accessToken, request.getState(), request.getResponseMode()).toHTTPResponse();
        }

        LOG.debug("location {}", response.getHeader("location"));

        ServletUtils.applyHTTPResponse(response, resp);
        return;
	}

    private URI getCleanUrl(URI redirectionURI) {
        String fragmentsOfSpa = redirectionURI.getFragment();
        URI cleanUrl;
        try {
            cleanUrl = new URI(redirectionURI.toString().replace("#" + fragmentsOfSpa, ""));
        } catch (URISyntaxException e) {
            throw new OAuthException("clean url cant be parsed", null);
        }
        return cleanUrl;
    }

	@Override
	protected void doGet(HttpServletRequest servletRequest, HttpServletResponse resp) throws ServletException, IOException {
	   authorize(servletRequest, resp);
	}

    /**
     * resolveAuthorizationRequest
     */
    private AuthorizationRequest resolveAuthorizationRequest(HttpServletRequest servletRequest) throws ParseException {

        if (isNotBlank(servletRequest.getParameter(CLIENT_ID_STR))) {
			return AuthorizationRequest.parse(extractURI(servletRequest), requestParameters(servletRequest));
    	}
    	
    	if ((contains(servletRequest.getQueryString(), CLIENT_ID_STR))) {
    		return AuthorizationRequest.parse(extractURI(servletRequest),servletRequest.getQueryString());
    	}

    	// if we are dealing with a returning SAMLREsponse we might consider parsing the relayState
    	if (servletRequest.getParameter("SAMLResponse") != null && servletRequest.getParameter("RelayState") != null){
    		try {
    			URL url = new URL(servletRequest.getParameter("RelayState"));
    			if (contains(url.getQuery(), CLIENT_ID_STR)){
    				return AuthorizationRequest.parse(url.getQuery());
    			}
    		} catch (Exception ex){
    			// Noop
    		}
    	}
        
        throw  new ParseException(String.format("unable to resolve AuthorizationRequest from %s", servletRequest.getRequestURI()));
    }

    private boolean contains(String queryString, String searchStr) {
        return queryString != null && queryString.contains(searchStr);
    }


	private boolean isNotBlank(String parameter) {
        return parameter != null && parameter.trim().length() > 0;
    }

	public Map<String, String> requestParameters(HttpServletRequest servletRequest){
		Enumeration<String> parameterNames = servletRequest.getParameterNames();
		Map<String, String> params = new HashMap<>();
		while (parameterNames.hasMoreElements()) {
			String param = parameterNames.nextElement();
			String value = servletRequest.getParameter(param);
            try {
                params.put(param, URLDecoder.decode(value, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                params.put(param, value);
            }
        }
		return params;
	}

    private URI extractURI(HttpServletRequest request) {
        try {
            String query = request.getQueryString() == null ? "" : "?" + request.getQueryString();
            return new URL(request.getScheme(), request.getServerName(), request.getServerPort(), request.getRequestURI()).toURI();
        } catch (Exception e) {
            LOG.warn("Error extracting auth/ URI: " + e.getMessage());
            return null;
        }
    }
}
