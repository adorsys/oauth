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
package de.adorsys.oauth.loginmodule.util;

import org.apache.commons.lang.StringUtils;

/**
 * We generally read property from the System Environment. If we don't find it there,
 * we read from the System Properties.
 * 
 * @author francis pouatcha
 *
 */
public class EnvUtils {

	public String getEnvThrowException(String key) {
		String prop = System.getenv(key);
		if (StringUtils.isBlank(prop))
			prop = System.getProperty(key);
		if (StringUtils.isBlank(prop))
			throw new IllegalStateException("Missing property " + key);
		return prop;
	}

	public String getEnv(String key, String defaultProp) {
		String prop = System.getenv(key);
		if (StringUtils.isBlank(prop))
			prop = System.getProperty(key);
		if (StringUtils.isBlank(prop))
			return defaultProp;
		return prop;
	}
	

}
