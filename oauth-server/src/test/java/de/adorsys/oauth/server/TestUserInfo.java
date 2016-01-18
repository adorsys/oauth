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
package de.adorsys.oauth.server;

import org.junit.Test;

/**
 * TestUserInfo
 */
public class TestUserInfo  {

    @Test
    public void testUserInfo() throws Exception {

//        String token = login();
//
//        CacheConfig cacheConfig = CacheConfig.custom()
//                .setMaxCacheEntries(1000)
//                .setMaxObjectSize(8192)
//                .build();
//
//        RequestConfig requestConfig = RequestConfig.custom()
//                .setConnectTimeout(30000)
//                .setSocketTimeout(30000)
//                .build();
//
//        CloseableHttpClient cachingClient = CachingHttpClients.custom()
//                .setCacheConfig(cacheConfig)
//                .setDefaultRequestConfig(requestConfig)
//                .build();
//
//        HttpCacheContext context = HttpCacheContext.create();
//        HttpGet httpGet = new HttpGet(getUserInfoEndpoint());
//        httpGet.setHeader("Authorization", new BearerAccessToken(token).toAuthorizationHeader());
//
//        CloseableHttpResponse response = cachingClient.execute(httpGet, context);
//        assertEquals(200, response.getStatusLine().getStatusCode());
//
////        for (Header header : response.getAllHeaders()) {
////            System.out.println(header);
////        }
//
//        String userInfo = readContent(response.getEntity());
//        assertNotNull(userInfo);
//
//        CacheResponseStatus responseStatus = context.getCacheResponseStatus();
//        System.out.println(responseStatus);
//        assertEquals(CacheResponseStatus.CACHE_MISS, responseStatus);
//        cachingClient.execute(httpGet, context);
//        responseStatus = context.getCacheResponseStatus();
//        System.out.println(responseStatus);
//        assertEquals(CacheResponseStatus.CACHE_HIT, responseStatus);

    }


}