/**
 * Copyright (C) Posten Norge AS
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
package no.digipost.security;

import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import java.util.Optional;

public final class HttpClient {

    public static final CloseableHttpClient create() {
        return create(Optional.empty());
    }

    public static final CloseableHttpClient createWithProxy(String proxyHost, int port) {
        return create(Optional.of(new HttpHost(proxyHost, port)));
    }

    public static final CloseableHttpClient create(Optional<HttpHost> proxy) {
        HttpClientBuilder builder = HttpClientBuilder.create()
            .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(4000).build())
            .setDefaultRequestConfig(RequestConfig.custom().setConnectionRequestTimeout(4000).setConnectTimeout(4000).setSocketTimeout(4000).build());
        proxy.ifPresent(p -> builder.setProxy(p));
        return builder.build();
    }
}
