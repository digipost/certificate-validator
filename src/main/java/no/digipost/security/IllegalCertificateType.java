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

import java.security.cert.Certificate;

public class IllegalCertificateType extends RuntimeException {

	IllegalCertificateType(Certificate illegalCertificate) {
		super(message(illegalCertificate));
	}

	IllegalCertificateType(Object unexpectedObject) {
		super(unexpectedObject instanceof Certificate ? message((Certificate) unexpectedObject) : message(unexpectedObject));
	}

	private static String message(Object unexpectedObject) {
		return "Expected a " + DigipostSecurity.X509 + " certificate, but got a " + unexpectedObject.getClass().getName();
	}

	private static String message(Certificate illegalCertificate) {
		return "Not a " + DigipostSecurity.X509 + " certificate. The given certificate of type " + illegalCertificate.getType() + " can not be used.";
	}

}
