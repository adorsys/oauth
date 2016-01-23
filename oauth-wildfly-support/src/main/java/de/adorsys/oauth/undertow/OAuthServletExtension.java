package de.adorsys.oauth.undertow;

import javax.servlet.ServletContext;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;

/**
 * OAuthServletExtension
 */
@SuppressWarnings("unused")
public class OAuthServletExtension implements ServletExtension {

    private static final String MECHANISM_NAME = "OAUTH";

    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
        deploymentInfo.addFirstAuthenticationMechanism(MECHANISM_NAME, new DelegateAuthenticationMechanism(servletContext));
    }
}
