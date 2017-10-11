package de.adorsys.oauth.client.protocol;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import de.adorsys.oauth.client.OAuthCredentialHasher;

import org.apache.http.HttpEntity;
import org.apache.http.client.cache.HttpCacheContext;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.cache.CacheConfig;
import org.apache.http.impl.client.cache.CachingHttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Properties;

/**
 * UserInfoResolver
 */
public class UserInfoResolver {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResolver.class);

    private URI userInfoEndpoint;

    private CloseableHttpClient cachingHttpClient;

    public static UserInfoResolver from(Map<String, String> parameters) {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        String userInfoEndpoint = parameters.get("userInfoEndpoint");
        if (userInfoEndpoint == null) {
            throw new IllegalStateException("Invalid userInfoEndpoint ");
        }
        userInfoResolver.setUserInfoEndpoint(userInfoEndpoint);

        Properties properties = new Properties();
        parameters
                .entrySet().stream()
                .filter(p -> p.getValue() != null)
                .forEach(p -> properties.put(p.getKey(), p.getValue()) );
        return userInfoResolver.initialize(properties);
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        try {
            this.userInfoEndpoint = new URI(userInfoEndpoint);
        }
        catch (NullPointerException | URISyntaxException e) {
            throw new IllegalStateException("Invalid userInfoEndpoint " + e.getMessage());
        }
    }

    public UserInfoResolver initialize(Properties properties) {
        return initialize(new UserInfoResolverConfig(properties));
    }

    public UserInfoResolver initialize() {
        return initialize(new UserInfoResolverConfig());
    }

    private UserInfoResolver initialize(UserInfoResolverConfig config) {

        if (userInfoEndpoint == null) {
            throw new IllegalStateException("UserInfoEndpoint missing");
        }

        CacheConfig cacheConfig = CacheConfig.custom()
                .setMaxCacheEntries(config.getMaxCacheEntries())
                .setMaxObjectSize(config.getMaxCacheObjectSize())
                .build();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(config.getConnectTimeout())
                .setConnectionRequestTimeout(config.getConnectionRequestTimeout())
                .setSocketTimeout(config.getSocketTimeout())
                .build();

        cachingHttpClient = CachingHttpClients.custom()
                .setCacheConfig(cacheConfig)
                .setDefaultRequestConfig(requestConfig)
                .setMaxConnTotal(config.getMaxTotalConnections())
                .setMaxConnPerRoute(config.getMaxConnectionsPerRoute())
                .build();
        return this;
    }

    public UserInfo resolve(AccessToken accessToken) {

        try {
            URI userInfoRequest = new URI(String.format("%s?id=%s", userInfoEndpoint.toString(), accessToken.getValue()));
            HttpGet httpGet = new HttpGet(userInfoRequest);
            LOG.debug("load userinfo from {} ", userInfoRequest);
            httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());

            HttpCacheContext context = HttpCacheContext.create();
            try (CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context)){
                //TODO mask accessToken
                LOG.debug("read userinfo {} {}", OAuthCredentialHasher.hashCredential(accessToken.getValue()), context.getCacheResponseStatus());
                HttpEntity entity = userInfoResponse.getEntity();
                if (userInfoResponse.getStatusLine().getStatusCode() != 200 || entity == null) {
                	LOG.debug("no userInfo available for {}", OAuthCredentialHasher.hashCredential(accessToken.getValue()));
                	return null;
                }
    
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                entity.writeTo(baos);
    
                return UserInfo.parse(baos.toString());
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        return String.format("userInfoEndpoint=%s", userInfoEndpoint);
    }

    private class UserInfoResolverConfig {
        private static final int DEFAULT_MAX_CACHE_ENTRIES = 1000;
        private static final int DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES = 8192;
        private static final int REQUEST_DEFAULT_CONNECT_TIMEOUT_MS = 3000;
        private static final int REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS = 3000;
        private static final int REQUEST_DEFAULT_SOCKET_TIMEOUT_MS = 3000;
        private static final int DEFAULT_HTTP_MAX_TOTAL_CONNECTIONS = 50;
        /** max. Connections per Route - dies ist erstmal der Defaultwert aus CacheConfig */
        private static final int DEFAULT_HTTP_CONNECTIONS_PER_ROUTE = 2;

        private static final String PARAM_MAX_CACHE_ENTRIES = "de.adorsys.oauth.cache.max.entries.number";
        private static final String PARAM_MAX_CACHE_OBJECT_SIZE_BYTES = "de.adorsys.oauth.cache.max.object.size.bytes";
        private static final String PARAM_REQUEST_DEFAULT_CONNECT_TIMEOUT_MS = "de.adorsys.oauth.request.connect.timeout.ms";
        private static final String PARAM_REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS = "de.adorsys.oauth.request.connection.request.timeout.ms";
        private static final String PARAM_REQUEST_DEFAULT_SOCKET_TIMEOUT_MS = "de.adorsys.oauth.request.socket.timeout.ms";
        private static final String PARAM_DEFAULT_MAX_TOTAL_CONNECTIONS = "de.adorsys.oauth.http.max.connections.number";
        private static final String PARAM_DEFAULT_HTTP_CONNECTIONS_PER_ROUTE = "de.adorsys.oauth.http.connections.per.route.number";

        private int maxCacheEntries = DEFAULT_MAX_CACHE_ENTRIES;
        private int maxCacheObjectSize = DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES;

        private int connectTimeout = REQUEST_DEFAULT_CONNECT_TIMEOUT_MS;
        private int connectionRequestTimeout = REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS;
        private int socketTimeout = REQUEST_DEFAULT_SOCKET_TIMEOUT_MS;

        private int maxTotalConnections = DEFAULT_HTTP_MAX_TOTAL_CONNECTIONS;
        private int maxConnectionsPerRoute = DEFAULT_HTTP_CONNECTIONS_PER_ROUTE;

        private Properties parameters;

        UserInfoResolverConfig(Properties parameters) {
            if (parameters != null) {
                this.parameters = parameters;

                maxCacheEntries = parseIntParameter(PARAM_MAX_CACHE_ENTRIES, DEFAULT_MAX_CACHE_ENTRIES);
                maxCacheObjectSize = parseIntParameter(PARAM_MAX_CACHE_OBJECT_SIZE_BYTES, DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES);
                connectTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_CONNECT_TIMEOUT_MS, REQUEST_DEFAULT_CONNECT_TIMEOUT_MS);
                connectionRequestTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS, REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS);
                socketTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_SOCKET_TIMEOUT_MS, REQUEST_DEFAULT_SOCKET_TIMEOUT_MS);
                maxTotalConnections = parseIntParameter(PARAM_DEFAULT_MAX_TOTAL_CONNECTIONS, DEFAULT_HTTP_MAX_TOTAL_CONNECTIONS);
                maxConnectionsPerRoute = parseIntParameter(PARAM_DEFAULT_HTTP_CONNECTIONS_PER_ROUTE, DEFAULT_HTTP_CONNECTIONS_PER_ROUTE);
            }
        }

        UserInfoResolverConfig() {
            //default values are set during fields inititialization
        }

        private int parseIntParameter(String parameterName, int defaultValue) {
            try {
                int value = Integer.parseInt(parameters.getProperty(parameterName));
                LOG.debug("Parametr {} is found. Actual value is: {}", parameterName, value);
                return value;
            }
            catch (NumberFormatException e) {
                LOG.debug("Parameter {} is not found, setting to default", parameterName);
                return defaultValue;
            }
        }

        int getMaxCacheEntries() {
            return maxCacheEntries;
        }

        int getMaxCacheObjectSize() {
            return maxCacheObjectSize;
        }

        int getConnectTimeout() {
            return connectTimeout;
        }

        int getConnectionRequestTimeout() {
            return connectionRequestTimeout;
        }

        int getSocketTimeout() {
            return socketTimeout;
        }

        int getMaxTotalConnections() {
            return maxTotalConnections;
        }

        int getMaxConnectionsPerRoute() {
            return maxConnectionsPerRoute;
        }
    }
}
