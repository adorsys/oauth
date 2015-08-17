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
        AuthConfigFactory authConfigFactory = AuthConfigFactory.getFactory();
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

        configProvider = new OAuthAuthConfigProvider(properties, authConfigFactory);
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        if (configProvider != null) {
            AuthConfigFactory.getFactory().removeRegistration(configProvider.getRegistrationId());
        }
    }
}
