package de.adorsys.oauth.client;

import static org.junit.Assert.*;

import org.junit.Test;

public class OAuthCredentialHasherTest {

    @Test
    public void testHashCredential() {
        String hashCredential = OAuthCredentialHasher.hashCredential("test");
        assertEquals("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", hashCredential);
    }
    
    @Test
    public void testHashCredentialNull() {
        String hashCredential = OAuthCredentialHasher.hashCredential(null);
        assertNull(hashCredential);
    }

}
