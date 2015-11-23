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

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.util.concurrent.TimeUnit;
import javax.ejb.EJB;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * TestToken
 */
public class TestTokenStore extends ArquillianBase {

    @Deployment
    public static Archive createDeployment() {
        return createTestWar();
    }
    
    @EJB
    private TokenStore tokenStore;

    @Test
    public void testToken() throws Exception {

        BearerAccessToken bearerAccessToken = new BearerAccessToken();
        
        String id = tokenStore.add(bearerAccessToken, null);
        assertEquals(id, bearerAccessToken.getValue());

        RefreshToken refreshToken = tokenStore.loadRefreshToken(id);
        assertNull(refreshToken);

        AccessToken accessToken = tokenStore.load(id);
        assertNotNull(accessToken);
        
        System.out.println(accessToken.toJSONString());

        assertEquals(accessToken, bearerAccessToken);

        tokenStore.remove(id);
        assertNull(tokenStore.load(id));
    }

    @Test
    public void testValid() throws Exception {
        long lifetime = 2;
        BearerAccessToken bearerAccessToken = new BearerAccessToken(lifetime, null);
        String id = tokenStore.add(bearerAccessToken, null);

        AccessToken accessToken = tokenStore.load(id);
        assertNotNull(accessToken);
        
        System.out.println(accessToken.toJSONString());

        assertTrue(tokenStore.isValid(id));
        
        try {
            TimeUnit.MILLISECONDS.sleep(lifetime * 1000 + 100);
        } catch (Exception e) {
            //
        }

        assertFalse(tokenStore.isValid(id));
        
        tokenStore.remove(id);
    }
}
