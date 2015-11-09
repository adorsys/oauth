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
