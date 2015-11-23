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
package de.adorsys.saml.idp.nl.surfnet.mujina;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
 
public class AssertionGenerator { 
	
    private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory(); 
 
    private final SubjectGenerator subjectGenerator; 
    private final AuthnStatementGenerator authnStatementGenerator = new AuthnStatementGenerator(); 
    private final AttributeStatementGenerator attributeStatementGenerator = new AttributeStatementGenerator(); 
 
    public AssertionGenerator(String issuingEntityName) { 
        super(); 
        subjectGenerator = new SubjectGenerator(); 
    } 
 
    public Assertion generateAssertion(String remoteIP, String userName, String roles, String recepientAssertionConsumerURL, 
    		int validForInSeconds, String inResponseTo, DateTime authnInstant, String idpUrl) { 
        AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME); 
        Assertion assertion = assertionBuilder.buildObject(); 
 
        Subject subject = subjectGenerator.generateSubject(recepientAssertionConsumerURL, validForInSeconds, userName, inResponseTo, remoteIP); 
 
		Issuer responseIssuer = new IssuerBuilder().buildObject();
		responseIssuer.setValue(idpUrl);
		assertion.setIssuer(responseIssuer); 

        AuthnStatement authnStatement = authnStatementGenerator.generateAuthnStatement(authnInstant); 
        assertion.getAuthnStatements().add(authnStatement); 
        assertion.setSubject(subject); 
 
        // assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(authToken.getAuthorities())); 
 
        final Map<String,String> attributes = new HashMap<String, String>(); 
        attributes.put("urn:mace:dir:attribute-def:uid", userName);
        attributes.put("Membership", roles);
        assertion.getAttributeStatements().add(attributeStatementGenerator.generateAttributeStatement(attributes)); 
 
        assertion.setID(UUID.randomUUID().toString()); 
        assertion.setIssueInstant(new DateTime()); 
 
        return assertion; 
    } 
}
