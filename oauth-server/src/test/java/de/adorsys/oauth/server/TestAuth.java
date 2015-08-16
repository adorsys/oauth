package de.adorsys.oauth.server;

import org.apache.commons.codec.binary.Base64;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.BeforeClass;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import java.net.HttpURLConnection;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * TestAuth
 */
public class TestAuth extends ArquillianBase {

    @Deployment
    public static Archive createDeployment() {
        return createTestWar();
    }

    @BeforeClass 
    public static void beforeClass() {
        HttpURLConnection.setFollowRedirects(false);
    }
    
    @Test @RunAsClient
    public void testAuthCode() throws Exception {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType(Value.CODE), getClientID())
                .endpointURI(getAuthEndpoint())
                .redirectionURI(getRedirect("test"))
                .build();
        
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));

        HTTPResponse response = httpRequest.send();
        
        response.ensureStatusCode(HTTPResponse.SC_FOUND);

        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(response);
        assertTrue(authorizationResponse.indicatesSuccess());

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;
        
        assertNull(successResponse.getAccessToken());
        assertNotNull(successResponse.getAuthorizationCode());

        TokenRequest tokenRequest = new TokenRequest(
                getTokenEndpoint(), 
                getClientID(), 
                new AuthorizationCodeGrant(successResponse.getAuthorizationCode(), getRedirect("test")));


        HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();
        tokenResponse.indicatesSuccess();

        AccessTokenResponse accessTokenResponse = AccessTokenResponse.parse(tokenResponse);
        assertNotNull(accessTokenResponse.getAccessToken());
        assertNotNull(accessTokenResponse.getRefreshToken());

        System.out.println("testAuthCode: " + accessTokenResponse.getAccessToken().toJSONString());

    }    
    
    @Test @RunAsClient
    public void testAuthImplizit() throws Exception {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType(Value.TOKEN), getClientID())
                .endpointURI(getAuthEndpoint())
                .redirectionURI(getRedirect("test"))
                .build();
        
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));

        HTTPResponse response = httpRequest.send();
        
        response.ensureStatusCode(HTTPResponse.SC_FOUND);

        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(response);
        assertTrue(authorizationResponse.indicatesSuccess());

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;
        
        assertNotNull(successResponse.getAccessToken());
        assertNull(successResponse.getAuthorizationCode());


        System.out.println("testAuthImplizit " + successResponse.getAccessToken().toJSONString());

    }
}