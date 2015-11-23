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

import java.util.Arrays;
import java.util.List;

import org.apache.catalina.valves.ValveBase;

import de.adorsys.oauth.loginmodule.authdispatcher.AuthenticatorMatcher;

public abstract class BaseAuthenticatorMatcher implements AuthenticatorMatcher {

	protected ValveBase valve = null;

	@Override
	public List<ValveBase> valves() {
		return Arrays.asList(valve);
	}
	
}
