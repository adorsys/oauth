package de.adorsys.oauth.loginmodule.saml;

import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.ws.message.decoder.MessageDecodingException;

public class DiksHTTPPostDecoder extends HTTPPostDecoder {


	@Override
	protected boolean compareEndpointURIs(String messageDestination,
			String receiverEndpoint) throws MessageDecodingException {
		// TODO Implement uri comparison without protocol scheme
		return true;
		// TODO Auto-generated method stub
//		return super.compareEndpointURIs(messageDestination, receiverEndpoint);
	}
}
