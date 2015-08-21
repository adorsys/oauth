package de.adorsys.oauth.saml.bridge;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
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

    private SamlAuthConfigProvider configProvider;

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        Map<String, String> properties = new HashMap<>();
        for (Entry<Object, Object> entry : System.getProperties().entrySet()) {
            if (entry.getKey().toString().startsWith("saml.")) {
                properties.put((String) entry.getKey(), (String) entry.getValue());
            }
        }

        ServletContext servletContext = servletContextEvent.getServletContext();
        Enumeration<String> paramEnum = servletContext.getInitParameterNames();
        while (paramEnum.hasMoreElements()) {
            String key = paramEnum.nextElement();
            if (!key.startsWith("saml.")) {
                continue;
            }
            properties.put(key, servletContext.getInitParameter(key));
        }

        configProvider = new SamlAuthConfigProvider(properties, AuthConfigFactory.getFactory());
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        if (configProvider != null) {
            AuthConfigFactory.getFactory().removeRegistration(configProvider.getRegistrationId());
        }
    }
}
