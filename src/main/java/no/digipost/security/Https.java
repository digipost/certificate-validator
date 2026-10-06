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
import java.util.Optional;

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


    /**
     * Try to find a client certificate in a {@link ServletRequest}.
     * Unlike {@link #extractClientCertificate(ServletRequest)}, this method <em>does not</em>
     * throw an exception if for any reason at all a client certificate can not be retrieved
     * from the given request.
     *
     * @param request The request to find the certificate in
     *
     * @return the found certificate, or {@link Optional#empty()} if none could be retrieved.
     */
    public static Optional<X509Certificate> findClientCertificate(ServletRequest request) {
        if (!request.isSecure()) {
            return Optional.empty();
        } else {
            Object candidate = resolveAttributeInstanceOrFirstOfArray(request, REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE);
            return candidate instanceof X509Certificate ? Optional.of((X509Certificate) candidate) : Optional.empty();
        }
    }


    /**
     * Extract an <em>expected present</em> client certificate from a {@link ServletRequest}, or
     * throw an exception if a client certificate is not present in the request, or the request
     * is not {@link ServletRequest#isSecure() secure} and contained certificates can not be trusted.
     *
     * @param request The request to extract the certificate from
     *
     * @return the found certificate
     *
     * @throws NotSecure if the request is not secure
     * @throws IllegalCertificateType if the found instance is not a X509 certificate
     */
    public static X509Certificate extractClientCertificate(ServletRequest request) {
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

        Object candidate = resolveAttributeInstanceOrFirstOfArray(request, REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE);
        if (candidate instanceof X509Certificate) {
            return (X509Certificate) candidate;
        } else {
            throw new IllegalCertificateType(candidate);
        }
    }

    private static Object resolveAttributeInstanceOrFirstOfArray(ServletRequest request, String attributeName) {
        Object certObj = request.getAttribute(REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE);
        if (certObj instanceof Object[] && ((Object[]) certObj).length > 0) {
            certObj = ((Object[])certObj)[0];
        }
        return certObj;
    }


    private Https() {}
}
