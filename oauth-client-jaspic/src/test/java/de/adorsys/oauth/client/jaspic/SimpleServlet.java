package de.adorsys.oauth.client.jaspic;

import java.io.IOException;
import java.io.Writer;
import java.security.Principal;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SimpleServlet
 */
@SuppressWarnings("unused")
@WebServlet(value="/hello")
public class SimpleServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private Principal principal;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        Writer writer = response.getWriter();
        //writer.append("Hello from ").append(principal.getName()).append(" [ ");
        writer.append("Hello from ").append(request.getUserPrincipal().getName()).append(" [ ");

        for (String role : new String[] {"user", "admin"}) {
            if (request.isUserInRole(role)) {
                writer.append(role).append(" ");
            }
        }
        writer.append("]");
    }
}
