package de.adorsys.oauth.server;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.PasswordCredential;
import io.undertow.server.HttpServerExchange;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.spec.ServletContextImpl;

/**
 * FormAuthenticationMatcher
 */
public class FormAuthenticationMatcher implements AuthenticatorMatcher {

    private static final String FORM_PASSWORD = "j_password";
    private static final String FORM_USERNAME = "j_username";

    private String loginPage;

    @Override
    public void initialize(ServletContext servletContext) {
        ServletContextImpl contextImpl = (ServletContextImpl) servletContext;
        loginPage = resolveLoginPage(contextImpl);
    }

    private String resolveLoginPage(ServletContextImpl contextImpl) {
        LoginConfig loginConfig = contextImpl.getDeployment().getDeploymentInfo().getLoginConfig();
        String result = loginConfig == null ? null : loginConfig.getLoginPage();
        if (result == null) {
            result = "/login.jsp";
        }
        return result;
    }

    @Override
    public boolean match(HttpServerExchange exchange, HttpServletRequest request) {
        String query = request.getQueryString();
        return query != null && query.contains("response_type") || request.getParameter("response_type") != null;
    }

    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();

        if ("POST".equals(request.getMethod())) {
            String username = request.getParameter(FORM_USERNAME);
            String password = request.getParameter(FORM_PASSWORD);

            Account account = securityContext.getIdentityManager().verify(username, new PasswordCredential(password.toCharArray()));
            if (account == null) {
                return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
            }

            securityContext.authenticationComplete(account, OAuthServletExtension.MECHANISM_NAME, false);
            return AuthenticationMechanismOutcome.AUTHENTICATED;
        }

        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();

        RequestDispatcher requestDispatcher = request.getRequestDispatcher(loginPage);
        try {
            requestDispatcher.forward(request, servletRequestContext.getServletResponse());
        } catch (Exception e) {
            //  throw new RuntimeException(e);
        }
        return new ChallengeResult(false);
    }



}
