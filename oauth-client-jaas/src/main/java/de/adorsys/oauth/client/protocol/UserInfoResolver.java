package de.adorsys.oauth.client.protocol;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * UserInfoResolver
 */
public class UserInfoResolver {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResolver.class);

    private URI userInfoEndpoint;

    private CloseableHttpClient cachingHttpClient;

    public void setUserInfoEndpoint(String userInfoEndpoint) {
        try {
            this.userInfoEndpoint = new URI(userInfoEndpoint);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid userInfoEndpoint " + e.getMessage());
        }
    }

    public void initialize() {

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

    }

    public UserInfo resolve(AccessToken accessToken) throws IOException {

        HttpGet httpGet = new HttpGet(createURI(accessToken));

        httpGet.setHeader("Authorization", new BearerAccessToken(accessToken.getValue()).toAuthorizationHeader());

        HttpCacheContext context = HttpCacheContext.create();
        CloseableHttpResponse userInfoResponse = cachingHttpClient.execute(httpGet, context);
        LOG.debug("read userinfo {} {}", accessToken.getValue(), context.getCacheResponseStatus());

        HttpEntity entity = userInfoResponse.getEntity();
        if (entity==null){
            LOG.info("no userInfo available for {}", accessToken.getValue());
            return null;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        entity.writeTo(baos);

        try {
            return UserInfo.parse(baos.toString());
        } catch (ParseException e) {
            throw new IOException(e);
        }
    }

    private URI createURI(AccessToken accessToken) throws IOException {
        try {
            return new URI(String.format("%s?id=%s", userInfoEndpoint.toString(), accessToken.getValue()));
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }

    }

    @Override
    public String toString() {
        return String.format("userInfoEndpoint=%s", userInfoEndpoint);
    }
}
