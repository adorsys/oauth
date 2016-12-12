package de.adorsys.oauth.client.protocol;

import org.junit.Test;

import java.util.HashMap;
import java.util.Properties;

/**
 * @author Denys Golubiev
 */
public class UserInfoResolverTest {

    @Test
    public void from_withContextParameters() throws Exception {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("userInfoEndpoint", "Endpoint");
        parameters.put("de.adorsys.oauth.cache.max.entries.number", "800");
        parameters.put("de.adorsys.oauth.cache.max.object.size.bytes", "32768");
        parameters.put("de.adorsys.oauth.request.connect.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.request.connection.request.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.request.socket.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.http.max.connections.number", "20");

        UserInfoResolver userInfoResolver = UserInfoResolver.from(parameters);
        userInfoResolver.setUserInfoEndpoint("Endpoint");
        userInfoResolver.initialize();
    }


    @Test(expected = IllegalStateException.class)
    public void from_shouldFailWithoutEnpointParameter() throws Exception {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("de.adorsys.oauth.cache.max.entries.number", "800");
        parameters.put("de.adorsys.oauth.cache.max.object.size.bytes", "32768");
        parameters.put("de.adorsys.oauth.request.connect.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.request.connection.request.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.request.socket.timeout.ms", "10000");
        parameters.put("de.adorsys.oauth.http.max.connections.number", "20");

        UserInfoResolver userInfoResolver = UserInfoResolver.from(parameters);
        userInfoResolver.setUserInfoEndpoint("Endpoint");
        userInfoResolver.initialize();
    }

    @Test(expected = IllegalStateException.class)
    public void setUserInfoEndpoint_shouldFailWithNull() {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.setUserInfoEndpoint(null);
    }

    @Test(expected = IllegalStateException.class)
    public void initialize_shouldFailWithoutEndpoint() throws Exception {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.initialize();
    }

    @Test
    public void initialize_withDefaultParameters() throws Exception {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.setUserInfoEndpoint("Endpoint");
        userInfoResolver.initialize();
    }

    @Test
    public void initialize_withDefaultParametersAndEmptyParametersMap() throws Exception {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.setUserInfoEndpoint("Endpoint");
        userInfoResolver.initialize(new Properties());
    }

    @Test
    public void initialize_withRequiredProperties() throws Exception {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.setUserInfoEndpoint("Endpoint");

        Properties properties = new Properties();
        properties.put("de.adorsys.oauth.cache.max.entries.number", "800");
        properties.put("de.adorsys.oauth.cache.max.object.size.bytes", "32768");
        properties.put("de.adorsys.oauth.request.connect.timeout.ms", "10000");
        properties.put("de.adorsys.oauth.request.connection.request.timeout.ms", "10000");
        properties.put("de.adorsys.oauth.request.socket.timeout.ms", "10000");
        properties.put("de.adorsys.oauth.http.max.connections.number", "20");

        userInfoResolver.initialize(properties);
    }

}