package de.adorsys.oauth.loginmodule.authdispatcher;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Realm;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatelessFormAuthenticator extends AuthenticatorBase {
	
	private static final String ORIGIN_PARAM = "origin";

	private static final Logger LOG = LoggerFactory.getLogger(StatelessFormAuthenticator.class);

	// Form based authentication constants
	public static final String FORM_ACTION = "/j_security_check";
	public static final String FORM_PASSWORD = "j_password";
	public static final String FORM_USERNAME = "j_username";
	public static final String EXCEPTION_ATTR = "javax.servlet.error.exception";
	
	protected String characterEncoding = null;

	@Override
	protected boolean authenticate(Request request, HttpServletResponse response, LoginConfig config)
			throws IOException {

		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			return true;
		}

		// Is this the action request from the login page?

		if ("GET".equals(request.getMethod())){
			showLoginPage(request, response, config);
		} if ("POST".equals(request.getMethod())) {
			// Yes -- Validate the specified credentials and redirect
			// to the error page if they are not correct
			Realm realm = context.getRealm();
			if (characterEncoding != null) {
				request.setCharacterEncoding(characterEncoding);
			}
			String username = request.getParameter(FORM_USERNAME);
			String password = request.getParameter(FORM_PASSWORD);
			if (LOG.isDebugEnabled())
				LOG.debug("Authenticating username '" + username + "'");
			principal = realm.authenticate(username, password);

			if (principal != null) {
				register(request, response, principal, "FORM", username, password);
				return true;
			}		
			showErrorPage(request, response, config);
		}

		return false;
	}
	
	private void showLoginPage(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
		RequestDispatcher disp = context.getServletContext().getRequestDispatcher(config.getLoginPage());
		try {
			disp.forward(request.getRequest(), response);
		} catch (Exception e) {
			LOG.warn("formAuthenticator.forwardLoginFail", e);
			request.setAttribute(EXCEPTION_ATTR, e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "formAuthenticator.forwardErrorFail");
		}
	}
	
	private void showErrorPage(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
		RequestDispatcher disp = context.getServletContext().getRequestDispatcher(config.getErrorPage());
		try {
			disp.forward(request.getRequest(), response);
		} catch (Exception e) {
			LOG.warn("formAuthenticator.forwardLoginFail", e);
			request.setAttribute(EXCEPTION_ATTR, e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "formAuthenticator.redirectLoginPage");
		}
	}

	public String getCharacterEncoding() {
		return characterEncoding;
	}

	public void setCharacterEncoding(String characterEncoding) {
		this.characterEncoding = characterEncoding;
	}
	
	

}
