package de.adorsys.oauth.client.undertow;

import de.adorsys.oauth.client.undertow.OAuthAuthenticationMechanism.Factory;

import javax.servlet.ServletContext;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;

/**
 * OAuthServletExtension
 */
@SuppressWarnings("unused")
public class OAuthServletExtension implements ServletExtension {

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        deploymentInfo.addAuthenticationMechanism("oauth", new Factory(servletContext));
    }
}
