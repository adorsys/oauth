package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.commons.lang.StringUtils;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SimpleGroup;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlResponseAuthenticator extends SamlRequestAuthenticator {
	public static final String SAML_ROLE_ATTRIBUTE_NAME="SAML_ROLE_ATTRIBUTE_NAME";
    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseAuthenticator.class);

    private String roleAttributeName;
	
	@PostConstruct
	public void postConstruct(){
		super.postConstruct();
		roleAttributeName = getEnv(SAML_ROLE_ATTRIBUTE_NAME,"Role");
	}

	@Override
	protected boolean authenticate(Request request,
			HttpServletResponse response, LoginConfig config)
			throws IOException {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		// Is this the action request from the client? We expect a get request.
		if ("GET".equals(request.getMethod())){
			redirectSamlRequest(request, response);
		} if ("POST".equals(request.getMethod())) {
			// Yes -- Validate the response fron the idp server and
			// to the error page if they are not correct
            Principal userInfo = checkSamlRespone(request);
            if (userInfo != null) {
            	register(request, response, principal, "SAML", userInfo.getName(), null);
            	return true;
            }
		}

        redirectSamlRequest(request, response);
        return false;
	}
	
    /**
     * checkSamlRespone
     */
    private Principal checkSamlRespone(HttpServletRequest request) throws IOException {
        String samlResponse = request.getParameter("SAMLResponse");
        if (samlResponse == null) {
            return null;
        }

        HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.setHttpServletRequest(request);
        try {
			decoder.initialize();
			decoder.decode();
		} catch (ComponentInitializationException | MessageDecodingException e) {
			throw new IOException(e);
		}
        Response response = (Response) decoder.getMessageContext().getMessage();

//        Signature signature = response.getSignature();
//        SignatureValidator.validate(signature, credential);
        
        List<String> groups = new ArrayList<String>();
        groups.add("oauth"); // default for oauth

        String name = null;
        for (Assertion assertion : response.getAssertions()) {
            if (assertion.getSubject() != null) {
                name = assertion.getSubject().getNameID().getValue();
            }
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
                for (Attribute attribute : statement.getAttributes()) {
                    if (!roleAttributeName.equals(attribute.getName())) {
                        continue;
                    }
                    for (XMLObject xmlObject : attribute.getAttributeValues()) {
                        if (xmlObject instanceof XSString) {
                            XSString xsString = (XSString) xmlObject;
                            groups.add(xsString.getValue());
                        }

                    }
                }
            }
        }
        
        SimpleGroup callerPrincipalGroup = new SimpleGroup(name);        
        SimpleGroup rolesGroup = new SimpleGroup(SecurityConstants.ROLES_IDENTIFIER);
        callerPrincipalGroup.addMember(rolesGroup);
        for (String string : groups) {
        	SimpleGroup role = new SimpleGroup(string);
        	rolesGroup.addMember(role);
		}
        
        return callerPrincipalGroup;
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
