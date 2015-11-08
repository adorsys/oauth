package de.adorsys.oauth.loginmodule.saml;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Container;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SimpleGroup;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlResponseAuthenticator extends SamlRequestAuthenticator {
	public static final String SAML_ROLE_ATTRIBUTE_NAME="SAML_ROLE_ATTRIBUTE_NAME";
    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseAuthenticator.class);

    private String roleAttributeName;
	
	@Override
	public void setContainer(Container container) {
		super.setContainer(container);
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
        
        List<String> groups = new ArrayList<String>();
        groups.add("oauth"); // default for oauth

        String name = null;
        for (Assertion assertion : response.getAssertions()) {
            if (assertion.getSubject() != null) {
                name = assertion.getSubject().getNameID().getValue();
            }
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
            	List<Attribute> attributes = statement.getAttributes();
            	for (Attribute attribute : attributes) {
                    if (!roleAttributeName.equals(attribute.getName())) {
                        continue;
                    }
                    List<XMLObject> attributeValues = attribute.getAttributeValues();
                    for (XMLObject xmlObject : attributeValues) {
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

}
