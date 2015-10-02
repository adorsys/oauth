package de.adorsys.oauth.server;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.Dependent;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * CustomClaim
 */
@Dependent
public class CustomClaim {

    private static final Logger LOG = LoggerFactory.getLogger(CustomClaim.class);

    /**
     * Adds all unknown Groups as claim to given UserInfo
     */
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

        for (Principal p : principals) {
            if (! (p instanceof Group) ) {
                continue;
            }

            switch (p.getClass().getName()) {
                case "org.glassfish.security.common.Group": // GlassFish
                case "org.apache.geronimo.security.realm.providers.GeronimoGroupPrincipal": // Geronimo
                case "weblogic.security.principal.WLSGroupImpl": // WebLogic
                    continue;
                case "org.jboss.security.SimpleGroup": // JBoss
                    if (p.getName().equals("Roles") || p.getName().equals("CallerPrincipal")) {
                        continue;
                    }
            }

            // unkown Group, add to custom groups
            groups.add((Group) p);
        }

        return groups;
    }
}
