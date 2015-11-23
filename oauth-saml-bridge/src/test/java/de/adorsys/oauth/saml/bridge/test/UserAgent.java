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

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

/**
 * UserAgent
 */
@SuppressWarnings("unused")
public class UserAgent {

    private HttpURLConnection connection;
    private boolean followRedirect;
    private URL url;
    private Matcher matcher;
    private Map<String, String> values;

    public UserAgent() {
        values = new HashMap<>();
    }

    /**
     * url
     */
    public UserAgent url(String url) {
        String value = resolveValue(url, false);
        if (value != null) {
            url = value;
        }
        try {
            this.url = new URL(url);
            System.out.printf("URL: %s%n", url);
            return this;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * followRedirect
     */
    public UserAgent followRedirect(boolean followRedirect) {
        try {
            this.followRedirect = followRedirect;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * authorize
     */
    public UserAgent authorize(String user, String password) {
        try {
            String authorization = String.format("Basic %s", Base64.encodeBase64String(String.format("%s:%s", user, password).getBytes()));
            connection.setRequestProperty("Authorization", authorization);
            System.out.printf("%s: %s%n", "Authorization", authorization);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * bearer
     */
    public UserAgent bearer(String token) {
        String value = resolveValue(token, false);
        if (value == null) {
            value = token;
        }
        try {
            String authorization = String.format("Bearer %s", value);
            connection.setRequestProperty("Authorization", authorization);
            System.out.printf("%s: %s%n", "Authorization", authorization);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * openConnection
     */
    public UserAgent openConnection() {
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(followRedirect);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * expect
     * @param expectedStatus
     */
    public UserAgent expect(int expectedStatus) {
        int status;
        try {
            if (connection == null) {
                openConnection();
            }
            status = connection.getResponseCode();
            System.out.printf("Status: %d%n", status);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        if (expectedStatus != status) {
            throw new IllegalStateException(String.format("Expect %d, got %d", expectedStatus, status));
        }
        return this;
    }

    /**
     *  redirect
     */
    public UserAgent redirect() {
        try {
            String redirect = connection.getHeaderField("Location");
            url = new URL(redirect);
            connection = null;
            System.out.printf("Redirect: %s://%s:%d%s%n", url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * status
     */
    public UserAgent status() {
        try {
            System.out.printf("Status: %s%n", connection == null ? "???" : String.valueOf(connection.getResponseCode()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * postUrlEncoded
     */
    public UserAgent postUrlEncoded(String... parameters) {
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            StringBuilder sb = new StringBuilder();
            for (String parameter : parameters) {
                sb.append(parameter).append("=").append(URLEncoder.encode(resolveValue(parameter), "UTF8"));
            }

            String content = sb.toString();
            connection.setRequestProperty("Content-Length", Integer.toString(content.length()));
            DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
            dataOutputStream.write(content.getBytes());

            System.out.printf("Post: %s %d bytes%n", url, content.length());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }


    /**
     * parseQuery
     */
    public UserAgent parseQuery(String pattern) {
        try {
            matcher = Pattern.compile(pattern).matcher(url.getQuery());
            if (!matcher.matches()) {
                System.out.println("No match");
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * parseContent
     */
    public UserAgent parseContent(String pattern) {
        if (!values.containsKey("content")) {
            storeContent();
        }
        String content = values.get("content");
        try {
            matcher = Pattern.compile(pattern).matcher(content);
            if (!matcher.matches()) {
                System.out.println("No match");
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * deflate
     */
    public UserAgent deflate(String parameter) {
        String value = resolveValue(parameter);
        try {
            Inflater inflater = new Inflater(true);
            inflater.setInput(Base64.decodeBase64(URLDecoder.decode(value, "UTF8")));
            byte[] deflated = new byte[5000];
            int length = inflater.inflate(deflated);

            if (!inflater.finished()) {
                throw new IllegalStateException("didn't allocate enough space to hold decompressed data");
            }
            inflater.end();
            values.put(parameter, new String(deflated, 0, length));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public UserAgent dumpXml(String parameter) {
        return dumpXml(parameter, false);
    }

    /**
     * dumpXml
     */
    public UserAgent dumpXml(String parameter, boolean base64) {
        String value = resolveValue(parameter);
        byte[] bytes = base64 ? Base64.decodeBase64(value) : value.getBytes();

        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

            StringWriter stringWriter = new StringWriter();
            StreamResult streamResult = new StreamResult(stringWriter);

            transformer.transform(new StreamSource(new ByteArrayInputStream(bytes)), streamResult);
            System.out.printf("%s:%n%s", parameter, stringWriter.toString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    /**
     * content
     */
    public UserAgent storeContent() {
        try {
            InputStream is = connection.getResponseCode() == 200 ? connection.getInputStream() : connection.getErrorStream();
            int length = connection.getHeaderFieldInt("Content-Length", -1);
            if (0 < length) {
                byte[] content = new byte[length];
                length = is.read(content, 0, length);
                values.put("content", new String(content));
                return this;
            }

            byte[] content = new byte[2048];
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (0 < (length = is.read(content))) {
                baos.write(content, 0, length);
            }
            values.put("content", baos.toString());

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    private String resolveValue(String name) {
        return resolveValue(name, true);
    }

    private String resolveValue(String name, boolean required) {
        String value = values.get(name);
        if (value == null && matcher != null) {
            try {
                value = matcher.group(name);
            } catch (Exception e) {
                //
            }
        }
        if (value == null && required) {
            throw new IllegalStateException(String.format("Parameter %s not found !", name));
        }
        return value;
    }


    public UserAgent showContent() {
        storeContent();
        System.out.printf("Content: %s%n", resolveValue("content"));
        return this;
    }

    public UserAgent showValue(String parameter) {
        System.out.printf("%s: %s%n", parameter, resolveValue(parameter));
        return this;
    }

    public void goodBye() {
        System.out.println("\nso long and thanks for all the fish !");
    }
}
