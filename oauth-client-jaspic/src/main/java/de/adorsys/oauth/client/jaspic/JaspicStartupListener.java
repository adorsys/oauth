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
package de.adorsys.oauth.client.jaspic;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * StartupListener
 */
@WebListener
@SuppressWarnings("unused")
public class JaspicStartupListener implements ServletContextListener {

    private OAuthAuthConfigProvider configProvider;

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        // extract all oauth-properties from servletContext
        Map<String, String> properties = new HashMap<>();
        ServletContext servletContext = servletContextEvent.getServletContext();

        Enumeration<String> paramEnum = servletContext.getInitParameterNames();
        while (paramEnum.hasMoreElements()) {
            String key = paramEnum.nextElement();
            if (!key.startsWith("oauth.")) {
                continue;
            }
            properties.put(key, servletContext.getInitParameter(key));
        }

        configProvider = new OAuthAuthConfigProvider(properties, AuthConfigFactory.getFactory());
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        if (configProvider != null) {
            AuthConfigFactory.getFactory().removeRegistration(configProvider.getRegistrationId());
        }
    }
}
