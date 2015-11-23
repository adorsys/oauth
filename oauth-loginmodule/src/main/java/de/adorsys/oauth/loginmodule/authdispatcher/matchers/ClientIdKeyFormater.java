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
package de.adorsys.oauth.loginmodule.authdispatcher.matchers;

/**
 * Format client id in a way displayable in env property keys. 
 * 
 * @author francis
 *
 */
public class ClientIdKeyFormater {
	private static final String AUTHENTICATOR_SUFFIX = "_AUTH";

	public String format(String clientId){
		return clientId.replace('.', '_') + AUTHENTICATOR_SUFFIX;
	}
}
