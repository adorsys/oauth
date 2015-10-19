/**
 * TestToken.java
 */
package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.commons.codec.binary.Base64;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.HttpURLConnection;

import static org.junit.Assert.assertNotNull;

public class TestToken extends ArquillianBase {

    @Deployment
    public static Archive createDeployment() {
        return createTestWar();
    }

    @BeforeClass
    public static void beforeClass() {
        HttpURLConnection.setFollowRedirects(false);
    }

    @Test
    @RunAsClient
    public void testPasswortGrant() throws Exception {
        //Resource owner credentials
        TokenRequest tokenRequest = new TokenRequest(
                getTokenEndpoint(),
                getClientID(),
                new ResourceOwnerPasswordCredentialsGrant("resourceowner", new Secret("resourceowner_pw")));

        //Client secret
        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        httpRequest.setAuthorization("Basic " + Base64.encodeBase64String("test:123456".getBytes()));

        //send
        HTTPResponse tokenResponse = httpRequest.send();

        tokenResponse.indicatesSuccess();

        AccessTokenResponse accessTokenResponse = AccessTokenResponse.parse(tokenResponse);
        assertNotNull(accessTokenResponse.getAccessToken());
        assertNotNull(accessTokenResponse.getRefreshToken());

        System.out.println("access token: " + accessTokenResponse.getAccessToken().toJSONString());
        System.out.println("refresh token: " + accessTokenResponse.getRefreshToken().toJSONString());
    }
}
