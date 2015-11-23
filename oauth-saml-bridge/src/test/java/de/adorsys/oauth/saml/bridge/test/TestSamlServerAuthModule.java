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
package de.adorsys.oauth.saml.bridge.test;

import java.io.File;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * TestSamlAuthModule
 */
@RunWith(Arquillian.class)
public class TestSamlServerAuthModule {

    @Deployment
    public static Archive createDeployment() {

        File[] dependencies = Maven.configureResolver().workOffline(false).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve("org.opensaml:opensaml-saml-impl").withTransitivity().asFile();

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(true, "de.adorsys.oauth.saml.bridge")
                .addAsLibraries(dependencies)
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource(new File("src/test/resources/jboss-web-saml.xml"), "jboss-web.xml")
                .addAsWebInfResource("web.xml")
                ;
    }

    @Test @RunAsClient
    public void testSaml2() throws Exception {

        new UserAgent()
                .url("http://localhost:8280/sample/hello")
                .followRedirect(false)
                .expect(302)
                .redirect()
                    .parseQuery("(SAMLRequest=)(?<SAMLRequest>.*$)")
                    .deflate("SAMLRequest")
                    .dumpXml("SAMLRequest")
                .expect(401)
                .openConnection()
                .authorize("jduke", "secret")
                .expect(404)
                    .parseContent("(.*ACTION=\")(?<Action>.*)(\">)(<INPUT TYPE=\"HIDDEN\" NAME=\"SAMLResponse\" )(VALUE=\")(?<SAMLResponse>.*)(\"/>.*)")
                    .dumpXml("SAMLResponse", true)
                .url("Action")
                .postUrlEncoded("SAMLResponse")
                .expect(200)
                .showContent()
        ;
    }

}
