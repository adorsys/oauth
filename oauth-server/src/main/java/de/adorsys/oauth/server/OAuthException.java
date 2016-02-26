/**
 * 
 */
package de.adorsys.oauth.server;

/**
 * @author sso
 *
 */
public class OAuthException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public OAuthException(String message, Throwable cause) {
		super(message, cause);
	}

}
