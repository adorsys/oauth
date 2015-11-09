package de.adorsys.oauth.loginmodule.saml;

import java.net.URI;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.jboss.security.PicketBoxLogger;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Procsses sucessfull SAML Response.
 *  
 * @author Francis Pouatcha
 */
public class Saml2LoginModule extends AbstractServerLoginModule {

	private static final Logger LOG = LoggerFactory.getLogger(Saml2LoginModule.class);
	private static final String DEFAULT_ROLE = "defaultRole";
	private transient SimpleGroup userRoles = new SimpleGroup("Roles");
   /** The login identity */
   private Principal identity;
   
	private URI restEndpoint;
	private static final CloseableHttpClient HTTP_CLIENT;
   
	static {
		PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
		HTTP_CLIENT = HttpClients.custom().setConnectionManager(cm).build();
	}
	
   HttpServletRequest servletRequest = null;
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		addValidOptions(new String[]{DEFAULT_ROLE});
		super.initialize(subject, callbackHandler, sharedState, options);
		try {
			servletRequest = (HttpServletRequest) PolicyContext
					.getContext(HttpServletRequest.class.getName());
		} catch (PolicyContextException e) {
			LOG.error(
					"unable to retrieve PolicyContext.getContext(HttpServletRequest): {}",
					e.getMessage());
		}
	}

	@Override
	public boolean login() throws LoginException {
		SimpleGroup samlPrincipal = (SimpleGroup) servletRequest.getAttribute(SamlConstants.SAML_PRINCIPAL_ATTRIBUTE_KEY);
		if(samlPrincipal==null) return false;
//		readOrCreateSAMLUser(samlPrincipal);
		try {
			identity = super.createIdentity(samlPrincipal.getName());
			Enumeration<Principal> members = samlPrincipal.members();
			while (members.hasMoreElements()) {
				Principal role = super.createIdentity(members.nextElement().getName());
				PicketBoxLogger.LOGGER.traceAssignUserToRole(role.getName());
				userRoles.addMember(role);
			}
		} catch (Exception e) {
			throw new LoginException(e.getMessage());
		}
		defaultRole();
		super.loginOk = true;
		return true;
	}

	private void defaultRole() {
		String defaultRole = (String) options.get(DEFAULT_ROLE);
		try {
			if (defaultRole == null || defaultRole.equals("")) {
				return;
			}
			Principal p = super.createIdentity(defaultRole);
			PicketBoxLogger.LOGGER.traceAssignUserToRole(defaultRole);
			userRoles.addMember(p);
		} catch (Exception e) {
			PicketBoxLogger.LOGGER.debugFailureToCreatePrincipal(defaultRole, e);
		}
	}

	protected Group[] getRoleSets() throws LoginException {
		Group[] roleSets = { userRoles };
		return roleSets;
	}

	@Override
	protected Principal getIdentity() {
		return identity;
	}
	
	/*
	private Principal readOrCreateSAMLUser(SimpleGroup samlUser) throws LoginException {
		HttpHost targetHost = new HttpHost(restEndpoint.getHost(), restEndpoint.getPort(), restEndpoint.getScheme());
		CredentialsProvider credsProvider = new BasicCredentialsProvider();
		String password = UUID.randomUUID().toString();
		String username = samlUser.getName();
		credsProvider.setCredentials(new AuthScope(targetHost.getHostName(), targetHost.getPort()),
				new UsernamePasswordCredentials(username, password));

		// Create AuthCache instance
		AuthCache authCache = new BasicAuthCache();
		// Generate BASIC scheme object and add it to the local auth cache
		BasicScheme basicAuth = new BasicScheme();
		authCache.put(targetHost, basicAuth);

		// Add AuthCache to the execution context
		HttpClientContext context = HttpClientContext.create();
		context.setCredentialsProvider(credsProvider);
		context.setAuthCache(authCache);

		HttpPost httpPost = new HttpPost(restEndpoint);
		
		List<String> roles  = new ArrayList<String>();
		Enumeration<Principal> members = samlUser.members();
		while (members.hasMoreElements()) {
			roles.add(members.nextElement().getName());
		}
		JSONArray jsonArray = new JSONArray(roles);
		StringEntity stringEntity;
		try {
			stringEntity = new StringEntity(jsonArray.toString());
		} catch (UnsupportedEncodingException e1) {
			throw new IllegalStateException(e1);
		}
		httpPost.setEntity(stringEntity);

		CloseableHttpResponse userInfoResponse = null;
		Principal principal = null;
		try {
			userInfoResponse = HTTP_CLIENT.execute(httpPost, context);
			if (userInfoResponse.getStatusLine().getStatusCode() != 200) {
				LOG.error("Authentication failed for user {}, restEndpoint {} HTTP Status {}", username, restEndpoint.toASCIIString(),
						userInfoResponse.getStatusLine());
				throw new LoginException("Authentication failed for user " +username + ", restEndpoint " + restEndpoint.toASCIIString() + " HTTP Status " + userInfoResponse.getStatusLine());
			}
			String userInfoJson = readUserInfo(userInfoResponse);
			JSONObject userInfo = new JSONObject(userInfoJson);
			String principalId = userInfo.getString("principal");
			if (principalId == null) {
				LOG.error("could not read  field 'principal' for user {}. Response: {}", username, userInfoJson);
				throw new LoginException("could not read  field 'principal' for user " + username +". Response: " + userInfoJson);
			}
			JSONArray returnedRoles = userInfo.getJSONArray("roles");

			principal = new SimplePrincipal(principalId);
			if (roles != null) {
				for (Object object : returnedRoles) {
					if (object instanceof String) {
						userRoles.addMember(new SimplePrincipal((String) object));
					}
				}
			}

			// we put them to shared stated that other login providers can also
			// authenticate
			sharedState.put("javax.security.auth.login.name", principalId);
			sharedState.put("javax.security.auth.login.password", password);
		} catch (IOException e) {
			throw new IllegalStateException("problem on http backend authentication", e);
		} catch (Throwable e) {
			e.printStackTrace();
		} finally {
			if (userInfoResponse != null) {
				try {
					userInfoResponse.close();
				} catch (IOException e) {
					; // NOOP
				}
			}
		}
		return principal;
	}
	
	private String readUserInfo(CloseableHttpResponse userInfoResponse) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		userInfoResponse.getEntity().writeTo(baos);
		String content = new String(baos.toByteArray(), "UTF-8");

		LOG.debug("read userinfo {}", content);
		return content;
	}
	 */
}
