package de.adorsys.saml.idp.nl.surfnet.mujina;
import java.util.Map;

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
            XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME); 
            stringValue.setValue(entry.getValue()); 
            attribute.getAttributeValues().add(stringValue); 
            attributeStatement.getAttributes().add(attribute); 
        } 
 
        return attributeStatement; 
    } 
}