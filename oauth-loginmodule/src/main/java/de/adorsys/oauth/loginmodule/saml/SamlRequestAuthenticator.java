package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlRequestAuthenticator extends AuthenticatorBase {
	public static final String SAML_KEY_STORE_FILE_NAME = "SAML_KEY_STORE_FILE_NAME";
	public static final String SAML_KEY_STORE_TYPE = "SAML_KEY_STORE_TYPE";
	public static final String SAML_KEY_STORE_PASSWORD = "SAML_KEY_STORE_PASSWORD";
	public static final String SAML_KEY_SIGN_KEY_ALIAS = "SAML_KEY_SIGN_KEY_ALIAS";
	public static final String SAML_KEY_SIGN_KEY_PASSWORD = "SAML_KEY_SIGN_KEY_PASSWORD";
	public static final String SAML_IDP_URL = "SAML_IDP_URL";

    private static final Logger LOG = LoggerFactory.getLogger(SamlRequestAuthenticator.class);
	
	private String idpUrl;
	protected KeyStoreX509CredentialAdapter credential;
	
	private SAMLPeerEntityContext entityContext;
	@PostConstruct
	public void postConstruct(){
		String keyStoreFile = getEnv(SAML_KEY_STORE_FILE_NAME, null);
		if(StringUtils.isNotBlank(keyStoreFile)){
			String storeType = getEnvThrowException(SAML_KEY_STORE_TYPE);
			char[] keyStorePassword = getEnvThrowException(SAML_KEY_STORE_PASSWORD).toCharArray();
			KeyStore keyStore = loadKeyStore(keyStoreFile, storeType, keyStorePassword);
			String signKeyAlias = getEnvThrowException(SAML_KEY_SIGN_KEY_ALIAS);
			char[] signKeyPassword = getEnvThrowException(SAML_KEY_SIGN_KEY_PASSWORD).toCharArray();
			credential = new KeyStoreX509CredentialAdapter(keyStore, signKeyAlias, signKeyPassword);
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
	protected void redirectSamlRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String consumerServiceURL = request.getRequestURL().toString();
        if (request.getQueryString() != null) {
            consumerServiceURL = String.format("%s?%s", consumerServiceURL, request.getQueryString());
        }

        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        authnRequest.setAssertionConsumerServiceURL(consumerServiceURL);
        authnRequest.setDestination(idpUrl);
        authnRequest.setForceAuthn(false);
        authnRequest.setID(UUID.randomUUID().toString());
        authnRequest.setIsPassive(false);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setVersion(SAMLVersion.VERSION_20);

        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        authnRequest.setNameIDPolicy(nameIDPolicy);

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(consumerServiceURL);
        authnRequest.setIssuer(issuer);
        
        MessageContext<SAMLObject> messageContext = new MessageContext<SAMLObject>();
        messageContext.setMessage(authnRequest);
        messageContext.addSubcontext(entityContext);

        if(credential!=null){
        	SignatureSigningParameters signingParameters = new SignatureSigningParameters();
        	signingParameters.setSigningCredential(credential);
        	SecurityParametersContext secParamsContext =
                messageContext.getSubcontext(SecurityParametersContext.class, true);
        	secParamsContext.setSignatureSigningParameters(signingParameters);
        	messageContext.addSubcontext(secParamsContext);

        	try {
        		SAMLMessageSecuritySupport.signMessage(messageContext);
        	} catch (SecurityException | MarshallingException | SignatureException e) {
        		throw new IOException(e);
        	}
        }
        
		
		HTTPPostEncoder postEncoder = new HTTPPostEncoder();
		postEncoder.setMessageContext(messageContext);
		postEncoder.setHttpServletResponse(response);

		try {
			postEncoder.initialize();
			postEncoder.encode();
		} catch (ComponentInitializationException | MessageEncodingException e) {
			throw new IOException(e);
		}
    }

	private KeyStore loadKeyStore(String keyStorFile, String storeType, char[] keyStorePassword) {
		try {
			if(StringUtils.isBlank(storeType))storeType=KeyStore.getDefaultType();
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
		} catch (Exception e){
			throw new IllegalStateException(e);
		}
	}
	
	private String getEnvThrowException(String key){
		String prop = System.getenv(key);
		if(StringUtils.isBlank(prop)) throw new IllegalStateException("Missing property " + key);
		return prop;
	}
	
	private String getEnv(String key, String defaultProp) {
		String prop = System.getenv(key);
		if(StringUtils.isBlank(prop)) return defaultProp;
		return prop;
	}

}
