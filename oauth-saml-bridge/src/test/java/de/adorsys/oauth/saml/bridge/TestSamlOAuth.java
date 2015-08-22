package de.adorsys.oauth.saml.bridge;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

/**
 * TestSamlAuthModule
 */
@Ignore
@RunWith(Arquillian.class)
public class TestSamlOAuth {

    @Deployment(name = "oauth")
    public static Archive createOAuthDeployment() {

        File[] dependencies = Maven.configureResolver().workOffline(true).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve("org.opensaml:opensaml-saml-impl", "de.adorsys:oauth-server", "de.adorsys:oauth-tokenstore-jpa")
                .withTransitivity().asFile();

        return ShrinkWrap.create(WebArchive.class, "oauth-server.war")
                .addPackages(true, "de.adorsys.oauth.saml.bridge")
                .addAsLibraries(dependencies)
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
                .addAsWebInfResource("web.xml")
                ;
    }

    @Test @RunAsClient
    public void testServlet() throws Exception {
        //
    }
}
