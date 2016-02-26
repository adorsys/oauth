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

import java.security.Principal;
import java.security.acl.Group;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;

public class RememberMeTokenUtil {

	private static final String SECRET_KEY = System.getProperty("oauth.remembercookie.secretkey");

	public static String serialize(LoginSessionToken loginSession, String callerPrincipal, List<String> roles) {
		JWTClaimsSet claimSet = new JWTClaimsSet.Builder().claim("principal", callerPrincipal).claim("roles", roles)
				.claim("loginSession", loginSession.getValue()).build();
		String encryptedToken = EncryptedTokenSerializer.serialize(claimSet, getSecretKey());
		return encryptedToken;
	}

	private static byte[] getSecretKey() {
		return new Base64(SECRET_KEY).decode();
	}
	
	public static LoginSessionToken getLoginSession(String token) {
		JWTClaimsSet claimSet = EncryptedTokenSerializer.deserialize(token, getSecretKey());
		try {
			return new LoginSessionToken(claimSet.getStringClaim("loginSession"));
		} catch (ParseException e) {
			throw new OAuthException("expected valid loginSession in cookie", null);
		}
	}

	public static Collection<Principal> deserialize(String token) {
		JWTClaimsSet claimSet = EncryptedTokenSerializer.deserialize(token, getSecretKey());

		try {
			Collection<Principal> preparedPrincipals = new ArrayList<>();
			SimplePrincipal principal = new SimplePrincipal(claimSet.getStringClaim("principal"));
			preparedPrincipals.add(principal);
			Group callerGroup = new SimpleGroup("CallerPrincipal");
			preparedPrincipals.add(callerGroup);
			callerGroup.addMember(principal);

			Group rolesGroup = new SimpleGroup("Roles");
			preparedPrincipals.add(rolesGroup);
			for (Object object : claimSet.getStringArrayClaim("roles")) {
				if (object instanceof String) {
					rolesGroup.addMember(new SimplePrincipal((String) object));
				}
			}
			return preparedPrincipals;
		} catch (ParseException e) {
			throw new OAuthException("expected valid roles and principal in cookie", null);
		}
	}

	public static boolean isEnabled() {
		return SECRET_KEY != null;
	}

}
