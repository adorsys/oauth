package de.adorsys.oauth.sample;

import java.io.IOException;
import java.io.Writer;
import java.security.Principal;
import java.util.Date;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SimpleServlet
 */
@WebServlet(value="/api/voucher")
public class VoucherServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private Principal principal;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Writer writer = response.getWriter();
        writer.append("current user ").append(principal.getName()).append(" [ ");

        for (String role : new String[] {"user", "admin"}) {
            if (request.isUserInRole(role)) {
                writer.append(role).append(" ");
            }
        }
        writer.append("] ").append(String.format("%1$td.%1$tm%1$ty %1$tH:%1$tM:%1$tS.%1$tL", new Date()));
    }
}
