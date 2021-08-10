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

import java.security.cert.CertPath;
import java.security.cert.Certificate;

import static no.digipost.security.DigipostSecurity.describe;

/**
 * This exception implies a bug in the certificate-validator library.
 */
public class InvalidState extends RuntimeException {

    public InvalidState(String message) {
        this(message, (Throwable) null);
    }

    public InvalidState(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidState(String message, CertPath certpath) {
        this(message, certpath, null);
    }

    public InvalidState(String message, CertPath certpath, Throwable cause) {
        super(message + " " + describe(certpath), cause);
    }

    public InvalidState(String message, Certificate certificate) {
        this(message, certificate, null);
    }

    public InvalidState(String message, Certificate certificate, Throwable cause) {
        super(message + " " + describe(certificate), cause);
    }
}
