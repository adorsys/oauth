package de.adorsys.oauth.server;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import io.undertow.security.idm.Account;

/**
 * OAuhtAccount
 */
public class OAuhtAccount implements Account {

    static final OAuhtAccount INSTANCE = new OAuhtAccount();

    @Override
    public Principal getPrincipal() {
        return new Principal() {
            @Override
            public String getName() {
                return "oauth";
            }
        };
    }

    @Override
    public Set<String> getRoles() {
        Set<String> result = new HashSet<>();
        result.add("oauth");
        return result;
    }
}
