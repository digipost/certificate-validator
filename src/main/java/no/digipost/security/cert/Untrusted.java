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
package no.digipost.security.cert;

import no.digipost.security.DigipostSecurity;

import java.security.cert.CertPath;
import java.security.cert.Certificate;

/**
 * Thrown in cases where a certificate or certificate path is treated as trusted,
 * but in fact cannot be trusted. If this exception is encountered, it typically
 * indicates a programming error, where one should first query if the certificate
 * is trusted, and <em>then</em> retrieve it.
 */
public class Untrusted extends RuntimeException {

	Untrusted(CertPath certpath) {
		this(certpath, null);
	}

	Untrusted(CertPath certpath, Throwable cause) {
		super(DigipostSecurity.describe(certpath), cause);
	}

	Untrusted(Certificate certificate) {
		this(certificate, null);
	}

	Untrusted(Certificate certificate, Throwable cause) {
		super("The certificate is not trusted: " + DigipostSecurity.describe(certificate), cause);
	}

}
