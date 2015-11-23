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
package de.adorsys.oauth.sample;

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
@WebServlet(value="/hello")
public class SimpleServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Inject
    private Principal principal;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        Writer writer = response.getWriter();
        writer.append("Hello from ").append(principal.getName()).append(" [ ");

        for (String role : new String[] {"user", "admin"}) {
            if (request.isUserInRole(role)) {
                writer.append(role).append(" ");
            }
        }
        writer.append("]");
    }
}
