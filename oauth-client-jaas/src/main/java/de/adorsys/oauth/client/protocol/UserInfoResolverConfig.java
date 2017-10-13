package de.adorsys.oauth.client.protocol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

class UserInfoResolverConfig {
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResolverConfig.class);

    private static final int DEFAULT_MAX_CACHE_ENTRIES = 1000;
    private static final int DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES = 8192;
    private static final int REQUEST_DEFAULT_CONNECT_TIMEOUT_MS = 3000;
    private static final int REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS = 3000;
    private static final int REQUEST_DEFAULT_SOCKET_TIMEOUT_MS = 3000;
    private static final int DEFAULT_MAX_HTTP_CONNECTIONS_TOTAL = 50;
    /** max. Connections per Route - this is a default value from CacheConfig */
    private static final int DEFAULT_MAX_HTTP_CONNECTIONS_PER_ROUTE = 2;

    private static final String PARAM_MAX_CACHE_ENTRIES = "de.adorsys.oauth.cache.max.entries.number";
    private static final String PARAM_MAX_CACHE_OBJECT_SIZE_BYTES = "de.adorsys.oauth.cache.max.object.size.bytes";
    private static final String PARAM_REQUEST_DEFAULT_CONNECT_TIMEOUT_MS = "de.adorsys.oauth.request.connect.timeout.ms";
    private static final String PARAM_REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS = "de.adorsys.oauth.request.connection.request.timeout.ms";
    private static final String PARAM_REQUEST_DEFAULT_SOCKET_TIMEOUT_MS = "de.adorsys.oauth.request.socket.timeout.ms";
    private static final String PARAM_DEFAULT_MAX_HTTP_CONNECTIONS_TOTAL = "de.adorsys.oauth.http.max.connections.number";
    private static final String PARAM_DEFAULT_MAX_HTTP_CONNECTIONS_PER_ROUTE = "de.adorsys.oauth.http.connections.per.route.number";

    private int maxCacheEntries = DEFAULT_MAX_CACHE_ENTRIES;
    private int maxCacheObjectSize = DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES;

    private int connectTimeout = REQUEST_DEFAULT_CONNECT_TIMEOUT_MS;
    private int connectionRequestTimeout = REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS;
    private int socketTimeout = REQUEST_DEFAULT_SOCKET_TIMEOUT_MS;

    private int maxTotalConnections = DEFAULT_MAX_HTTP_CONNECTIONS_TOTAL;
    private int maxConnectionsPerRoute = DEFAULT_MAX_HTTP_CONNECTIONS_PER_ROUTE;

    private Properties parameters;

    UserInfoResolverConfig(Properties parameters) {
        if (parameters != null) {
            this.parameters = parameters;

            maxCacheEntries = parseIntParameter(PARAM_MAX_CACHE_ENTRIES, DEFAULT_MAX_CACHE_ENTRIES);
            maxCacheObjectSize = parseIntParameter(PARAM_MAX_CACHE_OBJECT_SIZE_BYTES, DEFAULT_MAX_CACHE_OBJECT_SIZE_BYTES);
            connectTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_CONNECT_TIMEOUT_MS, REQUEST_DEFAULT_CONNECT_TIMEOUT_MS);
            connectionRequestTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS, REQUEST_DEFAULT_CONNECTION_REQUEST_TIMEOUT_MS);
            socketTimeout = parseIntParameter(PARAM_REQUEST_DEFAULT_SOCKET_TIMEOUT_MS, REQUEST_DEFAULT_SOCKET_TIMEOUT_MS);
            maxTotalConnections = parseIntParameter(PARAM_DEFAULT_MAX_HTTP_CONNECTIONS_TOTAL, DEFAULT_MAX_HTTP_CONNECTIONS_TOTAL);
            maxConnectionsPerRoute = parseIntParameter(PARAM_DEFAULT_MAX_HTTP_CONNECTIONS_PER_ROUTE, DEFAULT_MAX_HTTP_CONNECTIONS_PER_ROUTE);
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
