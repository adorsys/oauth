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

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import java.io.Serializable;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuthRoleLoginModule
 */
public class OAuthLoginModule implements LoginModule {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthLoginModule.class);

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean login() throws LoginException {

        NameCallback nameCallback = new NameCallback("name");
        PasswordCallback password = new PasswordCallback("password", false);
        try {
            callbackHandler.handle(new Callback[]{nameCallback, password});
        } catch (Exception x) {
            throw new LoginException(x.getMessage());
        }

        String name = nameCallback.getName();
        String bearer = new String(password.getPassword());

        HttpServletRequest request = resolveHttpRequest();

        try {

            UserInfo userInfo = (UserInfo) request.getAttribute(UserInfo.class.getName());
            if (userInfo == null) {
                //no userinfo - no oauth login
                LOG.info("no userinfo available as request parameter");
                return false;
            }

            LOG.info("login {}:{}", name, bearer);

            SimplePrincipal principal = new SimplePrincipal(name);
            subject.getPrincipals().add(principal);

            Group callerGroup = new SimpleGroup("CallerPrincipal");
            subject.getPrincipals().add(callerGroup);
            callerGroup.addMember(principal);

            Group bearerGroup = new SimpleGroup("Bearer");
            subject.getPrincipals().add(bearerGroup);
            bearerGroup.addMember(new SimplePrincipal(bearer));


            if (userInfo.getSubject().getValue().equals(name)) {
                Object claims = userInfo.getClaim("groups");
                LOG.info("UserInfo: {} {}", userInfo.getSubject().getValue(), claims);
                Group rolesGroup = new SimpleGroup("Roles");
                subject.getPrincipals().add(rolesGroup);
                if (claims != null) {
                    for (String group : (List<String>) claims) {
                        rolesGroup.addMember(new SimplePrincipal(group));
                    }
                }

                if (sharedState != null) {
                    sharedState.put("userInfo", userInfo);
                }
            }

            return true;

        } catch (Exception e) {
            throw new LoginException(e.getMessage());
        }
    }

    private HttpServletRequest resolveHttpRequest() throws LoginException {
        try {
            return (HttpServletRequest) PolicyContext.getContext(HttpServletRequest.class.getName());
        } catch (PolicyContextException e) {
            LOG.error("unable to extract HttpServletRequest from PolicyContext {} {}", e.getClass().getSimpleName(), e.getMessage());
            throw new LoginException(e.getMessage());
        }
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return logout();
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject = null;
        return true;
    }

    /**
     * SimplePrincipal
     */
    private static class SimplePrincipal implements Principal, Serializable {
        private static final long serialVersionUID = 1L;
        private final String name;

        public SimplePrincipal(String name) {
            this.name = name;
        }

        public java.lang.String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SimplePrincipal that = (SimplePrincipal) o;
            return name.equals(that.name);
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }
    }

    /**
     * SimpleGroup
     */
    private class SimpleGroup extends SimplePrincipal implements Group {
        private static final long serialVersionUID = 1L;
        private HashMap<Principal, Principal> members;

        public SimpleGroup(java.lang.String groupName) {
            super(groupName);
            members = new HashMap<>();
        }

        public boolean addMember(Principal member) {
            if (members.containsKey(member)) {
                return false;
            }
            members.put(member, member);
            return true;
        }

        public boolean isMember(Principal member) {
            if (members.containsKey(member)) {
                return true;
            }
            for (Principal principal : members.keySet()) {
                if (!(principal instanceof Group)) {
                    continue;
                }
                Group group = (Group) principal;
                return group.isMember(principal);
            }
            return false;
        }

        public Enumeration<Principal> members() {
            return Collections.enumeration(members.values());
        }

        public boolean removeMember(Principal user) {
            Object previous = members.remove(user);
            return previous != null;
        }
    }

}