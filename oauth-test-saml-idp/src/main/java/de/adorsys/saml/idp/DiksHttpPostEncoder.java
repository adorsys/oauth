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

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DiksHttpPostEncoder extends HTTPPostEncoder {
	private static final Logger LOG = LoggerFactory.getLogger(DiksHttpPostEncoder.class);

	public DiksHttpPostEncoder(VelocityEngine engine, String templateId) {
		super(engine, templateId);
	}


	@Override
	protected void signMessage(@SuppressWarnings("rawtypes") SAMLMessageContext messageContext)
			throws MessageEncodingException {
        SAMLObject outboundSAML = messageContext.getOutboundSAMLMessage();
        Credential signingCredential = messageContext.getOuboundSAMLMessageSigningCredential();

        if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
            SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

            @SuppressWarnings("unchecked")
			XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
                    Signature.DEFAULT_ELEMENT_NAME);
            Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
            
            signature.setSigningCredential(signingCredential);
            try {
                //TODO pull SecurityConfiguration from SAMLMessageContext?  needs to be added
                //TODO pull binding-specific keyInfoGenName from encoder setting, etc?
//            	String infoGeneratorName = X509KeyInfoGenerator.class.getName();
                prepareSignatureParams(signature, signingCredential, null);
            } catch (SecurityException e) {
                throw new MessageEncodingException("Error preparing signature for signing", e);
            }
            
            signableMessage.setSignature(signature);

            try {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
                if (marshaller == null) {
                    throw new MessageEncodingException("No marshaller registered for "
                            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
                }
                marshaller.marshall(signableMessage);

                Signer.signObject(signature);
            } catch (MarshallingException e) {
            	LOG.error("Unable to marshall protocol message in preparation for signing", e);
                throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
            } catch (SignatureException e) {
            	LOG.error("Unable to sign protocol message", e);
                throw new MessageEncodingException("Unable to sign protocol message", e);
            }
        }
	}


	@Override
	protected void logEncodedMessage(MessageContext messageContext) {
        if(messageContext.getOutboundMessage() != null){
            if (messageContext.getOutboundMessage().getDOM() == null) {
                try {
                    marshallMessage(messageContext.getOutboundMessage());
                } catch (MessageEncodingException e) {
                	LOG.error("Unable to marshall message for logging purposes: " + e.getMessage());
                    return;
                }
            }
            LOG.info("\n" + XMLHelper.prettyPrintXML(messageContext.getOutboundMessage().getDOM()));
        }
	}	
	
    public static void prepareSignatureParams(Signature signature, Credential signingCredential,
            SecurityConfiguration config) throws SecurityException {

        SecurityConfiguration secConfig;
        if (config != null) {
            secConfig = config;
        } else {
            secConfig = Configuration.getGlobalSecurityConfiguration();
        }

        // The algorithm URI is derived from the credential
        String signAlgo = signature.getSignatureAlgorithm();
        if (signAlgo == null) {
            signAlgo = secConfig.getSignatureAlgorithmURI(signingCredential);
            signature.setSignatureAlgorithm(signAlgo);
        }

        // If we're doing HMAC, set the output length
        if (SecurityHelper.isHMAC(signAlgo)) {
            if (signature.getHMACOutputLength() == null) {
                signature.setHMACOutputLength(secConfig.getSignatureHMACOutputLength());
            }
        }

        if (signature.getCanonicalizationAlgorithm() == null) {
            signature.setCanonicalizationAlgorithm(secConfig.getSignatureCanonicalizationAlgorithm());
        }

        if (signature.getKeyInfo() == null) {
	        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
	        factory.setEmitEntityCertificate(true);
	        KeyInfoGenerator kiGenerator = factory.newInstance();
//            KeyInfoGenerator kiGenerator = getKeyInfoGenerator(signingCredential, secConfig, keyInfoGenName);
            if (kiGenerator != null) {
                try {
                    KeyInfo keyInfo = kiGenerator.generate(signingCredential);
                    signature.setKeyInfo(keyInfo);
                } catch (SecurityException e) {
                	LOG.error("Error generating KeyInfo from credential", e);
                    throw e;
                }
            } else {
//            	LOG.info("No factory for named KeyInfoGenerator {} was found for credential type {}", keyInfoGenName,
//                        signingCredential.getCredentialType().getName());
            	LOG.info("No KeyInfo will be generated for Signature");
            }
        }
    }

	
	
}
