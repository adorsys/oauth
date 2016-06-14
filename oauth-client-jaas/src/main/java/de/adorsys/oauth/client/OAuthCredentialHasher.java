package de.adorsys.oauth.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

public final class OAuthCredentialHasher {

    private  OAuthCredentialHasher() {
    }
    
    public static String hashCredential(String credential) {
    	if (credential == null) {
    		return null;
    	}
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(credential.getBytes(StandardCharsets.UTF_8));
            String encodedHash = Base64.encodeBase64String(hash);
            return encodedHash;
        } catch (NoSuchAlgorithmException e) {
            throw new java.lang.IllegalStateException("unknown codec SHA-256",  e);
        }
    }

}
