package de.adorsys.oauth.tokenstore.mongodb;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.Map;

import org.bson.Document;
import org.junit.Test;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.server.LoginSessionToken;

public class TokenDocumentTest {

	@Test
	public void testAsDocumentAuthToken() {
		UserInfo userInfo = new UserInfo(new Subject("sso"));
		
		Date created = new Date();
		TokenDocument<BearerAccessToken> tokenDocument = new TokenDocument<BearerAccessToken>(new BearerAccessToken("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE", 3600, null), created, new ClientID("TESTCLIENTID"), new LoginSessionToken("XXX"), userInfo);
		tokenDocument.setRefreshTokenRef("YYY");
		Document mongoDocument = tokenDocument.asDocument();
		
		
		assertEquals("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE", mongoDocument.get("_id"));
		assertEquals(created, mongoDocument.getDate("created"));
		assertEquals("TESTCLIENTID", mongoDocument.getString("clientId"));
		assertEquals("sso", ((Map<String, Object>)mongoDocument.get("userInfo")).get("sub"));
		assertEquals("ACCESS", mongoDocument.get("type"));
		assertEquals("XXX", mongoDocument.get("sessionId"));
		assertEquals(created.getTime() + 3600 * 1000, mongoDocument.getDate("expires").getTime());
		assertEquals("YYY", mongoDocument.getString("refreshTokenRef"));
		
	}
	
	@Test
	public void testAsDocumentRefreshToken() {
		UserInfo userInfo = new UserInfo(new Subject("sso"));
		
		Date created = new Date();
		TokenDocument<RefreshToken> tokenDocument = new TokenDocument<RefreshToken>(new RefreshToken("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE"), created, new ClientID("TESTCLIENTID"), new LoginSessionToken("XXX"), userInfo);
		Document mongoDocument = tokenDocument.asDocument();
		
		
		assertEquals("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE", mongoDocument.get("_id"));
		assertEquals(created, mongoDocument.getDate("created"));
		assertEquals("TESTCLIENTID", mongoDocument.getString("clientId"));
		assertEquals("sso", ((Map<String, Object>)mongoDocument.get("userInfo")).get("sub"));
		assertEquals("REFRESH", mongoDocument.get("type"));
		assertEquals("XXX", mongoDocument.get("sessionId"));
		assertEquals(Long.MAX_VALUE, mongoDocument.getDate("expires").getTime());
	}

	@Test
	public void testFromAuthToken() {
		Document document = Document.parse("{ \"_id\" : \"lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE\", \"created\" : { \"$date\" :" +System.currentTimeMillis() +"}, \"clientId\" : \"TESTCLIENTID\", \"userInfo\" : { \"sub\" : \"sso\" }, \"type\" : \"ACCESS\", \"sessionId\" : \"XXX\", \"expires\" : { \"$date\" : " +(System.currentTimeMillis() + 3600000) + " }, \"refreshTokenRef\" : \"YYY\" }");
		TokenDocument<AccessToken> from = TokenDocument.from(document);
		assertEquals("YYY", from.getRefreshTokenRef());
		
		assertEquals(new UserInfo(new Subject("sso")).toJSONObject(), from.getUserInfo().toJSONObject());
		assertEquals("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE", from.getToken().getValue());
		assertEquals(3600l, ((BearerAccessToken)(AccessToken) from.getToken()).getLifetime());
		assertTrue(from.isValid());
	}
	
	@Test
	public void testFromRefreshToken() {
		Document document = Document.parse("{ \"_id\" : \"lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE\", \"created\" : { \"$date\" : 1454966308809 }, \"clientId\" : \"TESTCLIENTID\", \"userInfo\" : { \"sub\" : \"sso\" }, \"type\" : \"REFRESH\", \"sessionId\" : \"XXX\", \"authCode\" : \"YYY\" }");
		TokenDocument<RefreshToken> from = TokenDocument.from(document);
		assertEquals(new UserInfo(new Subject("sso")).toJSONObject(), from.getUserInfo().toJSONObject());
		assertEquals("lOZugWbWUN2rKborv-QqnZWlpAx2w3c_lP_89e89QVE", from.getToken().getValue());
		assertTrue(from.isValid());
	}

}
