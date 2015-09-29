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
@SuppressWarnings("UnnecessaryLocalVariable")
@RunWith(Arquillian.class)
public class TestSamlOAuth {

    @Deployment(name = "oauth")
    public static Archive createOAuthDeployment() {

        File[] dependencies = Maven.configureResolver().workOffline(false).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve("org.opensaml:opensaml-saml-impl", "de.adorsys:oauth-server", "de.adorsys:oauth-tokenstore-jpa")
                .withTransitivity().asFile();

        Archive archive = ShrinkWrap.create(WebArchive.class, "oauth-server.war")
                .addPackages(false, "de.adorsys.oauth.saml.bridge")
                .addAsLibraries(dependencies)
                .addAsWebInfResource(new File("src/test/resources/oauth-server/jboss-web.xml"))
                .addAsWebInfResource(new File("src/test/resources/oauth-server/web.xml"))
                ;
        //System.out.println(a.toString(true));
        return archive;
    }

    @Deployment(name = "sample")
    public static Archive createSampleDeployment() {

        return ShrinkWrap.create(WebArchive.class, "sample.war")
                .addPackages(false, "de.adorsys.oauth.saml.bridge.test")
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource(new File("src/test/resources/jboss-web-oauth.xml"), "jboss-web.xml")
                .addAsWebInfResource("web.xml")
                ;
    }

    @Test @RunAsClient
    public void testServlet() throws Exception {
        new UserAgent()
                .url("http://localhost:8280/sample/hello")
                .followRedirect(false)
                .expect(302)
                .redirect()  // to oauth
                .expect(302)
                    .redirect() // to saml-idp, from here : saml auth flow
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
                .expect(200) // back from saml auth, from here: auth grant flow
                .showContent()
                .parseContent("(.*access_token\":\")(?<accessToken>.*)(\".*)")
                .showValue("accessToken")
                .url("http://localhost:8280/sample/hello")  // and now with accessToken
                .openConnection()
                .bearer("accessToken")
                .expect(200)
                .showContent()
                .goodBye()

        ;
    }
}
