package de.adorsys.oauth.server;

import org.jboss.security.SubjectInfo;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;

import java.lang.reflect.Method;
import java.util.Collection;

/**
 * JBossSubjectInfo
 * picketlink changes the interface (sic) of RoleGroup
 * before 4.9 : List<Role> getRoles
 * after 4.9 : Collection<Role> getRoles ...
 * The compiled classes contains the type of the return value
 *
 * we have to support a wide range of picketboxes ( 4.9 is in eap 7)
 */
public class JBossSubjectInfo {

    private final SubjectInfo subjectInfo;
    private static final Method ROLES_METHOD;

    static {
        try {
            ROLES_METHOD = RoleGroup.class.getMethod("getRoles");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public JBossSubjectInfo(SubjectInfo subjectInfo) {
        this.subjectInfo = subjectInfo;
    }

    @SuppressWarnings("unchecked")
    public Collection<Role> getRoles() {

        RoleGroup roleGroup = subjectInfo.getRoles();
        try {
            return (Collection<Role>) ROLES_METHOD.invoke(roleGroup);
        } catch (Exception e) {
            throw new IllegalStateException("no possible to call 'getRoles'", e);
        }
    }
}
