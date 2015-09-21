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

import javax.servlet.ServletRequest;

import java.security.cert.X509Certificate;

/**
 * Utilities for working with certificates in secure (https) requests.
 * The class requires the Servlet API, i.e:
 * <pre>{@code
 * <dependency>
 *     <groupId>javax.servlet</groupId>
 *     <artifactId>javax.servlet-api</artifactId>
 *     <version>3.1.0</version>
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
	public static final String REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE = "javax.servlet.request.X509Certificate";


	public static X509Certificate extractClientCertificate(ServletRequest request) {
		if (!request.isSecure()) {
			throw new NotSecure(request);
		}

		Object certObj = request.getAttribute(REQUEST_CLIENT_CERTIFICATE_ATTRIBUTE);
		if(certObj instanceof Object[] && ((Object[]) certObj).length > 0) {
			certObj = ((Object[])certObj)[0];
		}

		if (certObj instanceof X509Certificate) {
			return (X509Certificate) certObj;
		} else {
			throw new IllegalCertificateType(certObj);
		}
	}


	private Https() {}
}
