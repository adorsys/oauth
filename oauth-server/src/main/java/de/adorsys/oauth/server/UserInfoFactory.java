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

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SubjectInfo;
import org.jboss.security.identity.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * UserInfoFactory - depends on JBoss
 */
@Dependent
public class UserInfoFactory {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoFactory.class);

    @Inject
    private Principal principal;

    /**
     * createUserInfo
     */
    public UserInfo createUserInfo(HttpServletRequest servletRequest) {
        Object object = servletRequest.getAttribute("userInfo");
        if (object != null && object instanceof UserInfo) {
            return (UserInfo) object;
        }

        SecurityContext context = SecurityContextAssociation.getSecurityContext();
        SubjectInfo subjectInfo = context.getSubjectInfo();
        String name = principal.getName();

        List<String> roles = new ArrayList<>();
        UserInfo userInfo = new UserInfo(new Subject(name));
        userInfo.setName(name);

        if (subjectInfo.getRoles() != null) {
            for (Role role : subjectInfo.getRoles().getRoles()) {
                roles.add(role.getRoleName());
            }
            userInfo.setClaim("groups", roles);
        }

        // add non role groups as claim to userinfo
        if (subjectInfo.getAuthenticatedSubject() != null) {
        	addCustomGroups(userInfo, subjectInfo.getAuthenticatedSubject().getPrincipals());
        }

        return userInfo;
    }

    public void addCustomGroups(UserInfo userInfo, Set<Principal> principals) {
        if (userInfo == null || principals == null) {
            LOG.error("Userinfo or Principals null");
            return;
        }

        List<Group> unknownGroups = getUnknownGroups(principals);

        for (Group prince : unknownGroups) {
            Principal other = prince.members().nextElement();
            userInfo.setClaim(prince.getName(), other.toString()); //json prince
        }
    }

    /**
     * Filter all known role groups
     *
     * @param principals
     * @return unknown groups
     */
    private List<Group> getUnknownGroups(Set<Principal> principals) {
        List<Group> groups = new ArrayList<>();

        for (Principal principal : principals) {
            if (! (principal instanceof Group) ) {
                continue;
            }

            switch (principal.getClass().getName()) {
                case "org.glassfish.security.common.Group": // GlassFish
                case "org.apache.geronimo.security.realm.providers.GeronimoGroupPrincipal": // Geronimo
                case "weblogic.security.principal.WLSGroupImpl": // WebLogic
                    continue;
                default: //  org.jboss.security.SimpleGroup or similar
                    if (principal.getName().equals("Roles") || principal.getName().equals("CallerPrincipal")) {
                        continue;
                    }
            }

            // unkown Group, add to custom groups
            groups.add((Group) principal);
        }

        return groups;
    }

}
