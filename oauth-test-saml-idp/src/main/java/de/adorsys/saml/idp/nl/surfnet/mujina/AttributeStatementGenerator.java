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
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
 
public class AttributeStatementGenerator { 
    private final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory(); 
 
    public AttributeStatement generateAttributeStatement(final Map<String, String> attributes) { 
        AttributeStatementBuilder attributeStatementBuilder = (AttributeStatementBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME); 
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject(); 
 
        AttributeBuilder attributeBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME); 
        XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME); 
 
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
        	
            Attribute attribute = attributeBuilder.buildObject(); 
            attribute.setName(entry.getKey());
            String value = entry.getValue();
            if(StringUtils.isNotBlank(value)){
	            String[] split = StringUtils.split(value, ",");
	            List<String> valueList = Arrays.asList(split);
	            for (String v : valueList) {
	            	XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME); 
	            	stringValue.setValue(v); 
	            	attribute.getAttributeValues().add(stringValue); 
				}
            }
            attributeStatement.getAttributes().add(attribute); 
        } 
 
        return attributeStatement; 
    } 
}