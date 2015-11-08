package de.adorsys.oauth.server;

import java.net.URI;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;


/**
 * AuthzResource
 */
@SuppressWarnings("unused")
@Path("auth")
@ApplicationScoped
public class AuthResource {

    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);

    @Context
    private HttpServletRequest servletRequest;

    @Context
    private ServletContext servletContext;

    @Inject
    private UserInfoFactory userInfoFactory;

    @Inject
    private TokenStore tokenStore;

    private long tokenLifetime;

    @PostConstruct
    public void postConstruct() {
        try {
            tokenLifetime = Long.valueOf(servletContext.getInitParameter("lifetime"));
        } catch (Exception e) {
            tokenLifetime = 8 * 3600;
        }

        LOG.info("token lifetime {}", tokenLifetime);
    }

    @POST
    @Consumes("application/x-www-form-urlencoded")
    public Response authorizePost() throws Exception {

        AuthorizationRequest request = resolveAuthorizationRequest();

        ResponseBuilder response = Response.status(302).header("Authorization", null); // remove existing auth ...
        
        if (request.getRedirectionURI() == null) {
            return response.location(
                    new AuthorizationErrorResponse(request.getEndpointURI(), OAuth2Error.INVALID_REQUEST, request.getState(), request.getResponseMode()).toURI())
                    .build();
        }

        if (servletRequest.getUserPrincipal() == null) {
            return response.location(
                    new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.UNAUTHORIZED_CLIENT, request.getState(), request.getResponseMode()).toURI())
                    .build();
        }

        if (request.getClientID() == null) {
            return response.location(
                    new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_CLIENT, request.getState(), request.getResponseMode()).toURI())
                    .build();
        }

        if (request.getResponseType() == null) {
            return response.location(
                    new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, request.getState(), request.getResponseMode()).toURI())
                    .build();
        }

        UserInfo userInfo = createUserInfo(request);
        LOG.debug(userInfo.toJSONObject().toJSONString());
        
        BearerAccessToken accessToken = new BearerAccessToken(tokenLifetime, request.getScope());

        if (request.getResponseType().impliesCodeFlow()) {
            AuthorizationCode authCode = new AuthorizationCode();
            LOG.info("impliesCodeFlow {}", authCode.toJSONString());
            
            tokenStore.add(accessToken, userInfo, authCode);
            return response.location(new AuthorizationSuccessResponse(request.getRedirectionURI(), authCode, null, request.getState(), request.getResponseMode()).toURI()).build();
        }

        LOG.info("impliesTokenFlow {}", accessToken.toJSONString());
        tokenStore.add(accessToken, userInfo);

        AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(request.getRedirectionURI(), null, accessToken, request.getState(), request.getResponseMode());
        String location = successResponse.toURI().toString();
        LOG.info("location {}", location);

        return response.location(new URI(location)).build();
    }

    @GET
    public Response authorizeGet() throws Exception {
        return authorizePost();

    }

    /**
     * resolveAuthorizationRequest
     */
    private AuthorizationRequest resolveAuthorizationRequest() throws ParseException {
    		
    	String CLIENT_ID_STR = "client_id";
    	if(isNotBlank(servletRequest.getParameter(CLIENT_ID_STR))){
			Map<String, String> params = toSingleParamMap(servletRequest);
			return AuthorizationRequest.parse(params );
    	}
    	
    	if((contains(servletRequest.getQueryString(), CLIENT_ID_STR))){
    		return AuthorizationRequest.parse(servletRequest.getQueryString());
    	}

    	// if we are dealing with a returning SAMLREsponse we might consider parsing 
    	// the relayState
    	if(servletRequest.getParameter("SAMLResponse")!=null && servletRequest.getParameter("RelayState")!=null){
    		try {
    			String serviceUrl = servletRequest.getParameter("RelayState");
    			URL url = new URL(serviceUrl);
    			if(contains(url.getQuery(), CLIENT_ID_STR)){
    				return AuthorizationRequest.parse(url.getQuery());
    			}
    		} catch (Exception ex){
    			// Noop
    		}
    	}
        
        throw  new ParseException(String.format("unable to resolve AuthorizationRequest from %s", servletRequest.getRequestURI()));
    }

    private boolean contains(String queryString, String searchStr) {
    	if(queryString==null) return false;
		return queryString.contains(searchStr);
	}


	private boolean isNotBlank(String parameter) {
		if(parameter==null) return false;
		return parameter.trim().length()>0;
	}


	private UserInfo createUserInfo(AuthorizationRequest request) {
        UserInfo userInfo = userInfoFactory.createUserInfo(servletRequest);

        if (request == null) {
            return userInfo;
        }

        // for what ever ...
        userInfo.setClaim("clientID", request.getClientID());
        if (request.getScope() != null) {
            userInfo.setClaim("scope", request.getScope());
        }

        return userInfo;
    }
	
	public Map<String, String> toSingleParamMap(HttpServletRequest servletRequest){
		Enumeration<String> parameterNames = servletRequest.getParameterNames();
		Map<String, String> params = new HashMap<String, String>();		
		while (parameterNames.hasMoreElements()) {
			String param = (String) parameterNames.nextElement();
			String value = servletRequest.getParameter(param);
			params.put(param, value);
		}
		return params;
	}
}
