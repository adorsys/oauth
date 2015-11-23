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
package de.adorsys.oauth.saml.bridge;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.metadata.AuthzService;
import org.opensaml.saml.saml2.metadata.impl.AuthzServiceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuthServerAuthModule - SAM
 */
@SuppressWarnings({"unused", "UnusedParameters", "FieldCanBeLocal", "rawtypes", "MismatchedReadAndWriteOfArray", "unchecked", "ConstantConditions"})
public class SamlServerAuthModule implements ServerAuthModule {

    private static final Logger LOG = LoggerFactory.getLogger(SamlServerAuthModule.class);

    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

    private CallbackHandler callbackHandler;
    private String idpUrl;
    private SAMLPeerEntityContext entityContext;

    @Override
    public Class[] getSupportedMessageTypes() {
        return SUPPORTED_MESSAGE_TYPES;
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler callbackHandler, Map properties) throws AuthException {
        this.callbackHandler = callbackHandler;
        this.idpUrl = (String) properties.get("saml.idp.url");

        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new AuthException(e.getMessage());
        }

        AuthzService authzService = new AuthzServiceBuilder().buildObject();
        authzService.setResponseLocation(idpUrl);
        authzService.setLocation(idpUrl);

        SAMLEndpointContext endpointContext = new SAMLEndpointContext();
        endpointContext.setEndpoint(authzService);

        entityContext = new SAMLPeerEntityContext();
        entityContext.addSubcontext(endpointContext);

    }

    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject subject) throws AuthException {
        return AuthStatus.SEND_SUCCESS;
    }

    @SuppressWarnings("ConstantConditions")
    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return AuthStatus.SUCCESS;
        }

        LOG.debug("request {}", request.getRequestURL());

        try {
            UserInfo userInfo = checkSamlRespone(request);
            if (userInfo != null) {
                return applyUserInfo(clientSubject, userInfo);
            }

            redirectSamlRequest(request, response);

        } catch (Exception e) {
            LOG.error("ups", e);
            throw new AuthException(e.getMessage());
        }

        return AuthStatus.FAILURE;
    }

    /**
     * redirectSamlRequest
     */
    private void redirectSamlRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        /*
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
              AssertionConsumerServiceURL="http://localhost:8080/sample/hello"
              Destination="http://localhost:8080/idp/"
              ForceAuthn="false"
              ID="ID_6056b6db-84b7-4800-85b1-3baafd7b0576"
              IsPassive="false"
              IssueInstant="2015-08-21T19:11:46.178Z"
              ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost:8080/sample/hello</saml:Issuer>
            <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
        </samlp:AuthnRequest>
         */

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

        MessageContext<SAMLObject> messageContext = new MessageContext();
        messageContext.setMessage(authnRequest);
        messageContext.addSubcontext(entityContext);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(messageContext);
        encoder.setHttpServletResponse(response);

        encoder.initialize();
        encoder.encode();
    }

    /**
     * checkSamlRespone
     */
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    private UserInfo checkSamlRespone(HttpServletRequest request) throws Exception {
        String samlResponse = request.getParameter("SAMLResponse");
        if (samlResponse == null) {
            return null;
        }

        HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.setHttpServletRequest(request);
        decoder.initialize();
        decoder.decode();
        Response response = (Response) decoder.getMessageContext().getMessage();

        List<String> groups = new ArrayList<>();
        groups.add("oauth"); // default for oauth

        String name = null;
        for (Assertion assertion : response.getAssertions()) {
            if (assertion.getSubject() != null) {
                name = assertion.getSubject().getNameID().getValue();
            }
            for (AttributeStatement statement : assertion.getAttributeStatements()) {
                for (Attribute attribute : statement.getAttributes()) {
                    if (!"Role".equals(attribute.getName())) {
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

        UserInfo userInfo = new UserInfo(new com.nimbusds.oauth2.sdk.id.Subject(name));
        userInfo.setName(name);
        userInfo.setClaim("groups", groups);
        request.setAttribute("userInfo", userInfo);
        return userInfo;
    }

    /**
     * applyUserInfo
     */
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    private AuthStatus applyUserInfo(Subject clientSubject, UserInfo userInfo) throws AuthException {
        try {

            String name = userInfo.getName();
            List<String> groups = (List<String>) userInfo.getClaim("groups");

            callbackHandler.handle(new Callback[] {
                    new CallerPrincipalCallback(clientSubject, name),
                    new GroupPrincipalCallback(clientSubject, groups.toArray(new String[groups.size()]))
            });

        } catch (IOException | UnsupportedCallbackException e) {
            throw new AuthException(e.getMessage());
        }

        return AuthStatus.SUCCESS;
    }


}
