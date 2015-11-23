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
package de.adorsys.saml.idp;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.AuthzServiceBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.adorsys.saml.idp.nl.surfnet.mujina.AssertionGenerator;
import de.adorsys.saml.idp.nl.surfnet.mujina.StatusGenerator;

@WebServlet(urlPatterns="/*")
public class IdpServlet extends HttpServlet {

	private static final long serialVersionUID = -4726333893148785903L;

	private static final Logger LOG = LoggerFactory
			.getLogger(IdpServlet.class);
	
	private XMLObjectBuilderFactory builderFactory;
	
	private String idpUrl = "http://docker:8081/saml.idp";
	private String idpEntityName = "saml.idp";
	protected KeyStoreX509CredentialAdapter credential;
	private AssertionGenerator assertionGenerator;
	private StatusGenerator statusGenerator;

	@Override
	public void init() throws ServletException {
		super.init();

		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new IllegalStateException(e);
		}
		builderFactory = org.opensaml.Configuration.getBuilderFactory();
		
		initVelocityEngine();

		String keyStoreFile = "/opt/jboss/standalone/certs/saml.idp.keystore";
		String storeType = "jks";
		char[] keyStorePassword = "storepass".toCharArray();
		KeyStore keyStore = loadKeyStore(keyStoreFile, storeType,
				keyStorePassword);
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = (String) aliases.nextElement();
				LOG.debug("Key alias: " + alias);
			}
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		String signKeyAlias = idpEntityName;
		char[] signKeyPassword = "keypass".toCharArray();
		try {
			Key key = keyStore.getKey(signKeyAlias, signKeyPassword);
			if (key == null)
				throw new IllegalStateException(
						"can not read saml signing key. ");
		} catch (UnrecoverableKeyException | KeyStoreException
				| NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		credential = new KeyStoreX509CredentialAdapter(keyStore, signKeyAlias,
				signKeyPassword);
		
		assertionGenerator = new AssertionGenerator(idpEntityName);
		statusGenerator = new StatusGenerator();
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		
        BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> inboundMessage = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>(); 
        inboundMessage.setInboundMessageTransport(new HttpServletRequestAdapter(req));
        HTTPPostDecoder decoder = new HTTPPostDecoder();
        try {
			decoder.decode(inboundMessage);
		} catch (MessageDecodingException | SecurityException e) {
			throw new IllegalStateException(e);
		}
        AuthnRequest authnRequest = (AuthnRequest) inboundMessage.getInboundSAMLMessage();
        String assertionConsumerServiceURL = authnRequest.getAssertionConsumerServiceURL();
		
//        URL url = new URL(assertionConsumerServiceURL);
//		String remoteIP = url.getProtocol()+"://"+url.getHost()+(url.getPort()>0?":"+url.getPort():"") + "/" + url.getPath(); 
		org.opensaml.saml2.core.Response authnResponse = generateAuthnResponse(assertionConsumerServiceURL, "adreas.boetscher", "GA_DIKS_STU_CM_BENUTZERKONTEN,XXXY",assertionConsumerServiceURL, 300, authnRequest.getID(), new DateTime());

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext.setInboundMessage(authnRequest);
		messageContext.setOutboundSAMLMessage(authnResponse);
		messageContext.setOutboundSAMLMessageSigningCredential(credential);
		Endpoint endpoint = new AuthzServiceBuilder().buildObject();
		endpoint.setLocation(assertionConsumerServiceURL);
		messageContext.setPeerEntityEndpoint(endpoint);
		messageContext.setRelayState(inboundMessage.getRelayState());

		
		boolean secure = StringUtils.containsIgnoreCase(idpUrl, "https://");
		HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(resp, secure);
		messageContext.setOutboundMessageTransport(responseAdapter);

		HTTPPostEncoder postEncoder = new DiksHttpPostEncoder(velocityEngine,"templates/saml2-post-binding.vm");
//		HTTPPostEncoder postEncoder = new HTTPPostEncoder(velocityEngine,"templates/saml2-post-binding.vm");
		try {
			postEncoder.encode(messageContext);
		} catch (MessageEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
	public org.opensaml.saml2.core.Response generateAuthnResponse(String remoteIP,
			String userName, String roles,
			String recepientAssertionConsumerURL, int validForInSeconds,
			String inResponseTo, DateTime authnInstant) {
		ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory
				.getBuilder(org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME);
		org.opensaml.saml2.core.Response authResponse = responseBuilder.buildObject();
		Issuer responseIssuer = new IssuerBuilder().buildObject();
		responseIssuer.setValue(idpUrl);

		Assertion assertion = assertionGenerator.generateAssertion(remoteIP,
				userName, roles, recepientAssertionConsumerURL, validForInSeconds,
				inResponseTo, authnInstant, idpUrl);
		authResponse.setIssuer(responseIssuer);
		authResponse.setID(UUID.randomUUID().toString());
		authResponse.setIssueInstant(new DateTime());
		authResponse.setInResponseTo(inResponseTo);
		authResponse.getAssertions().add(assertion);
		authResponse.setDestination(recepientAssertionConsumerURL);
		authResponse.setStatus(statusGenerator.generateStatus(StatusCode.SUCCESS_URI));
		return authResponse;
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

	private void initVelocityEngine() {
		velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
		velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
				"classpath");
		velocityEngine
				.setProperty("classpath.resource.loader.class",
						"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		try {
			velocityEngine.init();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}


}
