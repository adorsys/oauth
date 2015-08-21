package de.adorsys.oauth.saml.bridge;

import org.apache.commons.codec.binary.Base64;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

/**
 * TestSamlAuthModule
 */
@RunWith(Arquillian.class)
public class TestSamlAuthModule {

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
    public void testServlet() throws Exception {

        URL url = new URL("http://localhost:8280/sample/hello");

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);

        int statusCode = connection.getResponseCode();
        // 1. - redirect to idp
        if (statusCode != 302) {
            System.out.println("Redirect to idp expected");
            return;
        }

        String redirect = connection.getHeaderField("Location");
        url = new URL(redirect);
        System.out.printf("Redirect with SamlRequest to %s://%s:%d%s%n", url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
        dumpSaml(url.getQuery());

        connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        statusCode = connection.getResponseCode();

        // 2. auth
        if (statusCode == 401) {
            url = connection.getURL();
            System.out.printf("Login required from %s://%s:%d%s%n", url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
            connection = (HttpURLConnection) connection.getURL().openConnection();
            connection.setRequestProperty("Authorization", "Basic dGVzdDoxMjM0NTY=");
            connection.setInstanceFollowRedirects(false);
            statusCode = connection.getResponseCode();
        }

        // 3. some kind of post ... return 404 and javascript in body
        if (statusCode != 404) {
            System.out.printf("%d - 404 expected from %s%n", statusCode, connection.getURL());
            return;
        }

        InputStream is = connection.getErrorStream();
        byte[] buffer = new byte[2024];
        int read = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while (0 < (read = is.read(buffer))) {
            baos.write(buffer, 0, read);
        }

        String postResponse = baos.toString();
        Pattern pattern = Pattern.compile("(.*)(ACTION=\")(.*)(\">)(<INPUT TYPE=\"HIDDEN\" NAME=\"SAMLResponse\" )(VALUE=\")(.*)(\"/>.*)");
        Matcher matcher = pattern.matcher(postResponse);
        if (!matcher.matches()) {
            System.out.println("ups ..., wrong post response " + postResponse);
            return;
        }
        System.out.printf("Read SAMLResponse ...%n");

        String action = matcher.group(3);
        String samlResponse = matcher.group(7);
        dumpXml(Base64.decodeBase64(samlResponse.getBytes()), -1);

        samlResponse = "SAMLResponse=" + URLEncoder.encode(samlResponse, "UTF8");

        // 4. simulate java script part
        url = new URL(action);
        connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Content-Length", Integer.toString(samlResponse.length()));
        DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
        dataOutputStream.write(samlResponse.getBytes());

        System.out.printf("Post SAMLResponse to %s%n", url);
        statusCode = connection.getResponseCode();
        if (statusCode != 200) {
            System.out.println("ups, shit happens " + statusCode);
            return;
        }

        String content = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
        System.out.println(content);

    }

    private void dumpSaml(String saml) {
        try {
            int idx = saml.indexOf("=");
            Inflater inflater = new Inflater(true);
            inflater.setInput(Base64.decodeBase64(URLDecoder.decode(0 < idx ? saml.substring(idx + 1) : saml, "UTF8")));
            byte[] bytes = new byte[5000];
            int length = inflater.inflate(bytes);

            if (!inflater.finished()) {
                throw new RuntimeException("didn't allocate enough space to hold decompressed data");
            }

            inflater.end();
            dumpXml(bytes, length);
        } catch (Exception e) {
            System.out.println(saml);
        }

    }

    private void dumpXml(byte[] bytes, int length) throws Exception {
        if (length < 0) {
            length = bytes.length;
        }
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

        StringWriter stringWriter = new StringWriter();
        StreamResult streamResult = new StreamResult(stringWriter);

        transformer.transform(new StreamSource(new ByteArrayInputStream(bytes, 0, length)), streamResult);
        System.out.println(stringWriter.toString());
    }
}
