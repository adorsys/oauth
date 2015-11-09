package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.util.ParameterParser;
import org.apache.commons.httpclient.util.URIUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.jboss.security.SimpleGroup;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.AuthzServiceBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.adorsys.oauth.loginmodule.util.EnvUtils;

public class SamlRequestAuthenticator extends AuthenticatorBase {
	public static final String SAML_KEY_STORE_FILE_NAME = "SAML_KEY_STORE_FILE_NAME";
	public static final String SAML_KEY_STORE_TYPE = "SAML_KEY_STORE_TYPE";
	public static final String SAML_KEY_STORE_PASSWORD = "SAML_KEY_STORE_PASSWORD";
	public static final String SAML_KEY_SIGN_KEY_ALIAS = "SAML_KEY_SIGN_KEY_ALIAS";
	public static final String SAML_KEY_SIGN_KEY_PASSWORD = "SAML_KEY_SIGN_KEY_PASSWORD";
	public static final String SAML_IDP_URL = "SAML_IDP_URL";
	public static final String SAML_ROLE_ATTRIBUTE_NAMES="SAML_ROLE_ATTRIBUTE_NAMES";

	private static final Logger LOG = LoggerFactory.getLogger(SamlResponseAuthenticator.class);

	// URL des SAML IDP
	private String idpUrl;
	protected KeyStoreX509CredentialAdapter credential;

    private String roleAttributeNames;
	
	boolean initialized = false;
	
	protected EnvUtils envUtils = new EnvUtils();
	SecureRandomIdentifierGenerator secureRandomIdentifierGenerator = null;

	Map<String, String> idp2SpRoles = null;
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
		
		String keyStoreFile = envUtils.getEnv(SAML_KEY_STORE_FILE_NAME, null);
		if (StringUtils.isNotBlank(keyStoreFile)) {
			String storeType = envUtils.getEnvThrowException(SAML_KEY_STORE_TYPE);
			char[] keyStorePassword = envUtils.getEnvThrowException(
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
			String signKeyAlias = envUtils.getEnvThrowException(SAML_KEY_SIGN_KEY_ALIAS);
			char[] signKeyPassword = envUtils.getEnvThrowException(
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
		idpUrl = envUtils.getEnvThrowException(SAML_IDP_URL);

		roleAttributeNames = envUtils.getEnv(SAML_ROLE_ATTRIBUTE_NAMES,"Role,Roles,Membership,Memberships");
		
		idp2SpRoles = mapRoles();
		
		try {
			secureRandomIdentifierGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	protected boolean authenticate(Request request,
			HttpServletResponse response, LoginConfig config)
			throws IOException {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

        String samlResponse = request.getParameter("SAMLResponse");
        if (samlResponse != null) {
            Principal userInfo = checkSamlRespone(request);
            if (userInfo != null) {
            	register(request, response, principal, "SAML", userInfo.getName(), null);
            	return true;
            } else {
            	return false;
            }
        }
		
		redirectSamlRequest(request, response, null);

		return false;
	}

	/**
	 * redirectSamlRequest
	 */
	protected void redirectSamlRequest(HttpServletRequest request,
			HttpServletResponse response, Response samlResponse) throws IOException {

		String customerRequestServiceURL = request.getRequestURL().toString();
		URL url = new URL(customerRequestServiceURL);
		String consumerServiceURL = url.getProtocol() + "://" + url.getHost() + (url.getPort()>0?":"+url.getPort():"") + url.getPath();
		if (request.getQueryString() != null) {
			customerRequestServiceURL = String.format("%s?%s", customerRequestServiceURL,
					request.getQueryString());
		}

		AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
		authnRequest.setAssertionConsumerServiceURL(consumerServiceURL);
		authnRequest.setDestination(idpUrl);
		authnRequest.setForceAuthn(false);
		authnRequest.setID(secureRandomIdentifierGenerator.generateIdentifier());
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
		messageContext.setRelayState(customerRequestServiceURL);

		
		boolean secure = StringUtils.containsIgnoreCase(consumerServiceURL, "https://");
		HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(response, secure);
		messageContext.setOutboundMessageTransport(responseAdapter);

		HTTPPostEncoder postEncoder = new HTTPPostEncoder(velocityEngine,"templates/saml2-post-binding.vm");
		try {
			postEncoder.encode(messageContext);
		} catch (MessageEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

    /**
     * checkSamlRespone
     */
    @SuppressWarnings({ "deprecation", "rawtypes", "unchecked" })
	protected Principal checkSamlRespone(Request request) throws IOException {
        String samlResponse = request.getParameter("SAMLResponse");
        if (samlResponse == null) {
            return null;
        }
        BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>(); 
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        HTTPPostDecoder decoder = new HTTPPostDecoder();
        try {
			decoder.decode(messageContext);
		} catch (MessageDecodingException | SecurityException e) {
			throw new IllegalStateException(e);
		}

        Response response = (Response) messageContext.getInboundSAMLMessage();

//        Signature signature = response.getSignature();
//        SignatureValidator.validate(signature, credential);
        String relayState = request.getParameter("RelayState");;
        if(StringUtils.isBlank(relayState))relayState = messageContext.getRelayState();
        if(StringUtils.isBlank(relayState)){
        	throw new IllegalStateException("Missing redicret information.");
        }
        
        // Check is relay state is only the query string part of the request or a full 
        // URL.
        String query = null;
        if(StringUtils.startsWithIgnoreCase(relayState, "http")){
            URL originalUrl = new URL(relayState);
            query = originalUrl.getQuery();
        } else {
            query = relayState;
        }
        if (StringUtils.isBlank(query)){
        	throw new IllegalStateException("Missing redicret information.");
        }
        
        query = URIUtil.decode(query);
        ParameterParser parameterParser = new ParameterParser();
        List parse = parameterParser.parse(query, '&');
        for (Object object : parse) {
        	NameValuePair nv = (NameValuePair) object;
        	String parameter = request.getParameter(nv.getName());
        	if(StringUtils.isBlank(parameter)){
        		String[] values = new String[]{nv.getValue()};
        		request.addParameter(nv.getName(), values);
        	}
		}
        // set back the query string so oauth module can process the request.
        request.setQueryString(query);
        
        List<String> groups = new ArrayList<String>();

        String principalName = null;
        for (Assertion assertion : response.getAssertions()) {
            if (assertion.getSubject() != null && StringUtils.isBlank(principalName)) {
                principalName = assertion.getSubject().getNameID().getValue();
            }
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
            	List<Attribute> attributes = statement.getAttributes();
            	for (Attribute attribute : attributes) {
                    if (!StringUtils.containsIgnoreCase(roleAttributeNames,attribute.getName())) {
                        continue;
                    }
                    List<XMLObject> attributeValues = attribute.getAttributeValues();
                    for (XMLObject xmlObject : attributeValues) {
                    	if (xmlObject instanceof XSString) {
                    		XSString xsString = (XSString) xmlObject;
                    		String idpRole = xsString.getValue();
                    		String spRole = idp2SpRoles.get(idpRole); 
                    		groups.add(spRole);
                    	}
					}
                }
            }
        }
        
        SimpleGroup callerPrincipalGroup = new SimpleGroup(principalName);        
        for (String string : groups) {
        	SimpleGroup role = new SimpleGroup(string);
        	callerPrincipalGroup.addMember(role);
		}
        
        return callerPrincipalGroup;
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

	// SAML_IDP_ROLES
	public static final String SAML_IDP_ROLES="saml_idp_roles";
	public static final String SAML_IDP_ROLE_PREFIX="saml_idp_";

	private Map<String, String> mapRoles(){
		String role_keys = envUtils.getEnv(SAML_IDP_ROLES, null);
		if(StringUtils.isBlank(role_keys)) return mapDefaults();
		String[] split = StringUtils.split(role_keys);
		Map<String, String> result = new HashMap<String, String>();
		for (String role_key : split) {
			String roles = envUtils.getEnvThrowException(SAML_IDP_ROLE_PREFIX+role_key);
			String[] roleArray = StringUtils.split(roles);
			if(roleArray!=null && roleArray.length>0){
				for (String role : roleArray) {
					result.put(role, role_key);
				}
			}
		}
		return result;
	}

	private Map<String, String> mapDefaults() {
		Map<String, String> result = new HashMap<String, String>();
		result.put("GA_DIKS_STU_CM_BENUTZERKONTEN", "diksadmin");
		result.put("GA_DIKS_STU_NACHRICHTENDIALOG", "postboxadmin");
		return result;
	}
}
