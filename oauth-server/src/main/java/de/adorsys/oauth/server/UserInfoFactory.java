package de.adorsys.oauth.server;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SubjectInfo;
import org.jboss.security.identity.Role;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

/**
 * UserInfoFactory - depends on JBoss
 */
@Dependent
public class UserInfoFactory {

    @Inject
    private Principal principal;

    @Inject
    private CustomClaim customClaim;

    /**
     * resolveAuthorizationRequest
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
        customClaim.addCustomGroups(userInfo, subjectInfo.getAuthenticatedSubject().getPrincipals());

        return userInfo;
    }
}
