package de.adorsys.oauth.server;

import static org.junit.Assert.assertEquals;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Test;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;

public class EncryptedTokenSerializerTest {

	@Test
	public void testSerialite() {
		EncryptedTokenSerializer encryptedTokenSerializer = new EncryptedTokenSerializer();
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("roles", Arrays.asList("test")).build();
		String serializedToken = encryptedTokenSerializer.serialize(claimsSet, key);
		
		JWTClaimsSet deserialize = encryptedTokenSerializer.deserialize(serializedToken, key);
		assertEquals(new ArrayList<>(Arrays.asList("test")), deserialize.getClaim("roles"));
		System.out.println(serializedToken);
		System.out.println(Base64.encode(key));
		
	}

}
