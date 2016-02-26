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

import java.text.ParseException;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class EncryptedTokenSerializer {
	private static final JWSHeader HEADER = new JWSHeader(JWSAlgorithm.HS256);
	private static final JWEHeader JWE_HEADER = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).contentType("JWT").build();
	
	public static String serialize(JWTClaimsSet claimsSet, byte[] key) {
		try {
			// Create HMAC signer
			JWSSigner signer = new MACSigner(key);

			SignedJWT signedJWT = new SignedJWT(HEADER, claimsSet);

			// Apply the HMAC
			signedJWT.sign(signer);

			// Create JWE object with signed JWT as payload
			
			JWEObject jweObject = new JWEObject(
					JWE_HEADER,
					new Payload(signedJWT));

			// Perform encryption
			jweObject.encrypt(new DirectEncrypter(key));

			// Serialise to JWE compact form
			String jweString = jweObject.serialize();
			return jweString;
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
	}

	public static JWTClaimsSet deserialize(String serializedToken, byte[] key) {
		try {
			JWEObject jweObject = JWEObject.parse(serializedToken);
			jweObject.decrypt(new DirectDecrypter(key));
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			signedJWT.verify(new MACVerifier(key));
			JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
			return jwtClaimsSet;
		} catch (ParseException e) {
			throw new IllegalStateException(e);
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
	}
}
