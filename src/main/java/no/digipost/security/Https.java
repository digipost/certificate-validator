/*
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

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Collections.unmodifiableList;
import static java.util.stream.Collectors.toList;

/**
 * Utilities for working with certificates in secure (https) requests.
 * The class requires the Jakarta Servlet API, i.e:
 * <pre>{@code
 * <dependency>
 *     <groupId>jakarta.servlet</groupId>
 *     <artifactId>jakarta.servlet-api</artifactId>
 *     <version>5.0.0</version> <!-- or 6.0.0 -->
 * </dependency>
 * }</pre>
 *
 */
public class Https {

    /**
     * The attribute key for retrieving the client {@link X509Certificate} set by a servlet container for secure
     * (https) requests.
     *
     * @see ServletRequest#getAttribute(String)
     */
    public static final String REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";


    public static X509Certificate extractClientCertificate(ServletRequest request) {
        List<X509Certificate> chain = extractClientCertificateChain(request);
        if (chain.isEmpty()) {
            throw new IllegalCertificateType(request.getAttribute(REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE));
        }
        return chain.get(0);
    }

    public static List<X509Certificate> extractClientCertificateChain(ServletRequest request) {
        if (!request.isSecure()) {
            String resourceDescription;
            if (request instanceof HttpServletRequest) {
                HttpServletRequest httpRequest = (HttpServletRequest) request;
                resourceDescription = httpRequest.getMethod() + ": " + httpRequest.getRequestURI();
            } else {
                resourceDescription = request.toString();
            }
            throw new NotSecure(ServletRequest.class, resourceDescription);
        }

        Object certObj = request.getAttribute(REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE);
        if (certObj instanceof Object[]) {
            return unmodifiableList(Arrays.stream((Object[]) certObj)
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .collect(toList()));
        } else if (certObj instanceof X509Certificate) {
            return singletonList((X509Certificate) certObj);
        } else {
            return emptyList();
        }
    }


    private Https() {}
}
