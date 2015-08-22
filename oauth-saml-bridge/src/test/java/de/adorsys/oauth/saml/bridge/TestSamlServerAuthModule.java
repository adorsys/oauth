package de.adorsys.oauth.saml.bridge;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

/**
 * TestSamlAuthModule
 */
@RunWith(Arquillian.class)
public class TestSamlServerAuthModule {

    @Deployment
    public static Archive createDeployment() {

        File[] dependencies = Maven.configureResolver().workOffline(true).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve("org.opensaml:opensaml-saml-impl").withTransitivity().asFile();

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(true, "de.adorsys.oauth.saml.bridge")
                .addAsLibraries(dependencies)
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
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
                    .parseContent("(.*)(ACTION=\")(?<Action>.*)(\">)(<INPUT TYPE=\"HIDDEN\" NAME=\"SAMLResponse\" )(VALUE=\")(?<SAMLResponse>.*)(\"/>.*)")
                    .dumpXml("SAMLResponse", true)
                .url("Action")
                .postUrlEncoded("SAMLResponse")
                .expect(200)
                .showContent()
        ;
    }

}
