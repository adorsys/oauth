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
import org.apache.http.impl.client.cache.memcached.SHA256KeyHashingScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

/**
 * UserInfoResolver
 */
public class UserInfoResolver {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResolver.class);

    private URI userInfoEndpoint;

    private CloseableHttpClient cachingHttpClient;

    public static UserInfoResolver from(Map<String, String> properties) {
        UserInfoResolver userInfoResolver = new UserInfoResolver();
        userInfoResolver.setUserInfoEndpoint(properties.get("userInfoEndpoint"));
        return userInfoResolver.initialize();
    }

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        try {
            this.userInfoEndpoint = new URI(userInfoEndpoint);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid userInfoEndpoint " + e.getMessage());
        }
    }

    public UserInfoResolver initialize() {

        if (userInfoEndpoint == null) {
            throw new IllegalStateException("UserInfoEndpoint missing");
        }

        CacheConfig cacheConfig = CacheConfig.custom()
                .setMaxCacheEntries(1000)
                .setMaxObjectSize(8192)
                .build();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(30000)
                .setSocketTimeout(30000)
                .build();

        cachingHttpClient = CachingHttpClients.custom()
                .setCacheConfig(cacheConfig)
                .setDefaultRequestConfig(requestConfig)
                .build();
        return this;
    }

    public UserInfo resolve(AccessToken accessToken) {

        try {
            URI userInfoRequest = new URI(String.format("%s?id=%s", userInfoEndpoint.toString(), accessToken.getValue()));
            HttpGet httpGet = new HttpGet(userInfoRequest);

            httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());

            HttpCacheContext context = HttpCacheContext.create();
            CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context);
            LOG.debug("read userinfo {} {}", OAuthCredentialHasher.hashCredential(accessToken.getValue()), context.getCacheResponseStatus());

            HttpEntity entity = userInfoResponse.getEntity();
            if (entity==null){
                LOG.debug("no userInfo available for {}", accessToken.getValue());
                return null;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            entity.writeTo(baos);

            return UserInfo.parse(baos.toString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        return String.format("userInfoEndpoint=%s", userInfoEndpoint);
    }
}
