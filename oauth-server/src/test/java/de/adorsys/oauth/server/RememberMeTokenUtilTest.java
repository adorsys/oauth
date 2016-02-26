package de.adorsys.oauth.server;

import static org.junit.Assert.assertThat;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;

import org.hamcrest.Matchers;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class RememberMeTokenUtilTest {
	
	@BeforeClass
	public static void before() {
		System.setProperty("oauth.remembercookie.secretkey", "veCT7Q/V+YE8hdBPVwceCKC6dyrDsVyVFOm+n4J+htY=");
	}
	
	@AfterClass
	public static void after() {
		System.getProperties().remove("oauth.remembercookie.secretkey");
	}

	@Test
	public void testSerializeDeserialize() {
		String tokenString = RememberMeTokenUtil.serialize(new LoginSessionToken(), "kilgrave", Arrays.asList("role1", "role2"));
		Collection<Principal> deserialize = RememberMeTokenUtil.deserialize(tokenString);
		assertThat(deserialize, Matchers.<Principal>iterableWithSize(3));
	}
	
	@Test
	public void testGetLoginSession() {
		LoginSessionToken loginSession = new LoginSessionToken();
		String tokenString = RememberMeTokenUtil.serialize(loginSession, "kilgrave", Arrays.asList("role1", "role2"));
		LoginSessionToken loginSessionExtracted  = RememberMeTokenUtil.getLoginSession(tokenString);
		assertThat(loginSession, Matchers.is(loginSessionExtracted));
	}
	
	

}
