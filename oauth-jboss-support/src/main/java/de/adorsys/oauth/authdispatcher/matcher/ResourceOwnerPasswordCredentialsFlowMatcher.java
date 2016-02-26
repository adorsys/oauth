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
package de.adorsys.oauth.authdispatcher.matcher;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import de.adorsys.oauth.authdispatcher.FixedServletUtils;
import de.adorsys.oauth.server.ResourceOwnerPasswordCredentialFlowValve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Christian Brandenstein
 */
public class ResourceOwnerPasswordCredentialsFlowMatcher extends BaseAuthenticatorMatcher  {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceOwnerPasswordCredentialsFlowMatcher.class);

    public ResourceOwnerPasswordCredentialsFlowMatcher() {
        valve = new ResourceOwnerPasswordCredentialFlowValve();
    }

    @Override
    public ValveBase match(HttpServletRequest request, AuthorizationRequest authorizationRequest) {
        TokenRequest tokenRequest = null;
        try {
            tokenRequest = (TokenRequest) PolicyContext.getContext(TokenRequest.class.getName());
        } catch (PolicyContextException e) {
            LOG.error("policy context exception", e);
        }
        if (tokenRequest == null) {
            return null;
        }

        AuthorizationGrant authorizationGrant = tokenRequest.getAuthorizationGrant();
        if (authorizationGrant.getType() == GrantType.PASSWORD) {
            return valve;
        }
        return null;
    }
}
