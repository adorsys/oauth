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
            } catch (Exception e) {
                // Auch bei einem Timeout die Exception weiterwerfen
                throw new IllegalStateException(e);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        return String.format("userInfoEndpoint=%s", userInfoEndpoint);
    }

}
