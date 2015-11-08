package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.AuthzServiceBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlRequestAuthenticator extends AuthenticatorBase {
	public static final String SAML_KEY_STORE_FILE_NAME = "SAML_KEY_STORE_FILE_NAME";
	public static final String SAML_KEY_STORE_TYPE = "SAML_KEY_STORE_TYPE";
	public static final String SAML_KEY_STORE_PASSWORD = "SAML_KEY_STORE_PASSWORD";
	public static final String SAML_KEY_SIGN_KEY_ALIAS = "SAML_KEY_SIGN_KEY_ALIAS";
	public static final String SAML_KEY_SIGN_KEY_PASSWORD = "SAML_KEY_SIGN_KEY_PASSWORD";
	public static final String SAML_IDP_URL = "SAML_IDP_URL";
    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseAuthenticator.class);

	private String idpUrl;
	protected KeyStoreX509CredentialAdapter credential;

	boolean initialized = false;
	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
		
		if(!initialized){
			initialized=true;
			try {
				DefaultBootstrap.bootstrap();
			} catch (ConfigurationException e) {
				throw new IllegalStateException(e);
			}
		}
		
		initVelocityEngine();
		
		String keyStoreFile = getEnv(SAML_KEY_STORE_FILE_NAME, null);
		if (StringUtils.isNotBlank(keyStoreFile)) {
			String storeType = getEnvThrowException(SAML_KEY_STORE_TYPE);
			char[] keyStorePassword = getEnvThrowException(
					SAML_KEY_STORE_PASSWORD).toCharArray();
			KeyStore keyStore = loadKeyStore(keyStoreFile, storeType,
					keyStorePassword);
			try {
				Enumeration<String> aliases = keyStore.aliases();
				while (aliases.hasMoreElements()) {
					String alias = (String) aliases.nextElement();
					LOG.debug("Key alias: " + alias);
				}
			} catch (Exception ex){
				throw new IllegalStateException(ex);
			}
			String signKeyAlias = getEnvThrowException(SAML_KEY_SIGN_KEY_ALIAS);
			char[] signKeyPassword = getEnvThrowException(
					SAML_KEY_SIGN_KEY_PASSWORD).toCharArray();
			try {
				Key key = keyStore.getKey(signKeyAlias, signKeyPassword);
				if(key==null) throw new IllegalStateException("can not reab saml signing key. ");
			} catch (UnrecoverableKeyException | KeyStoreException
					| NoSuchAlgorithmException e) {
				throw new IllegalStateException(e);
			}
			credential = new KeyStoreX509CredentialAdapter(keyStore,
					signKeyAlias, signKeyPassword);
		}
		idpUrl = getEnvThrowException(SAML_IDP_URL);
	}

	@Override
	protected boolean authenticate(Request request,
			HttpServletResponse response, LoginConfig config)
			throws IOException {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		redirectSamlRequest(request, response);

		return false;
	}

	/**
	 * redirectSamlRequest
	 */
	protected void redirectSamlRequest(HttpServletRequest request,
			HttpServletResponse response) throws IOException {

		String consumerServiceURL = request.getRequestURL().toString();
		if (request.getQueryString() != null) {
			consumerServiceURL = String.format("%s?%s", consumerServiceURL,
					request.getQueryString());
		}

		AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
		authnRequest.setAssertionConsumerServiceURL(consumerServiceURL);
		authnRequest.setDestination(idpUrl);
		authnRequest.setForceAuthn(false);
		authnRequest.setID(UUID.randomUUID().toString());
		authnRequest.setIsPassive(false);
		authnRequest.setIssueInstant(new DateTime(System.currentTimeMillis()));
		authnRequest
				.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		authnRequest.setVersion(SAMLVersion.VERSION_20);

		NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
		nameIDPolicy.setAllowCreate(true);
		nameIDPolicy
				.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		authnRequest.setNameIDPolicy(nameIDPolicy);

		Issuer issuer = new IssuerBuilder().buildObject();
		issuer.setValue(consumerServiceURL);
		authnRequest.setIssuer(issuer);

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext.setOutboundSAMLMessage(authnRequest);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);
		Endpoint endpoint = new AuthzServiceBuilder().buildObject();
		endpoint.setLocation(idpUrl);
		messageContext.setPeerEntityEndpoint(endpoint);

		
		boolean secure = StringUtils.containsIgnoreCase(consumerServiceURL, "https://");
		HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(response, secure);
//		ByteArrayOutputStream bos = new ByteArrayOutputStream();
//		OutputStreamOutTransportAdapter transportAdapter = new OutputStreamOutTransportAdapter(bos);
		messageContext.setOutboundMessageTransport(responseAdapter);

		HTTPPostEncoder postEncoder = new HTTPPostEncoder(velocityEngine,"templates/saml2-post-binding.vm");
		try {
			postEncoder.encode(messageContext);
		} catch (MessageEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	private KeyStore loadKeyStore(String keyStorFile, String storeType,
			char[] keyStorePassword) {
		try {
			if (StringUtils.isBlank(storeType))
				storeType = KeyStore.getDefaultType();
			KeyStore ks = KeyStore.getInstance(storeType);
			java.io.FileInputStream fis = null;
			try {
				fis = new java.io.FileInputStream(keyStorFile);
				ks.load(fis, keyStorePassword);
			} finally {
				if (fis != null) {
					fis.close();
				}
			}
			return ks;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private String getEnvThrowException(String key) {
		String prop = System.getenv(key);
		if (StringUtils.isBlank(prop))
			throw new IllegalStateException("Missing property " + key);
		return prop;
	}

	protected String getEnv(String key, String defaultProp) {
		String prop = System.getenv(key);
		if (StringUtils.isBlank(prop))
			return defaultProp;
		return prop;
	}
	
	private VelocityEngine velocityEngine;
	private void initVelocityEngine(){
		velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        try {
			velocityEngine.init();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}		
	}

}
