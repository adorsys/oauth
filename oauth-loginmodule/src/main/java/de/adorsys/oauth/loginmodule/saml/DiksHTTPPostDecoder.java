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
