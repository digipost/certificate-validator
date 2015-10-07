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

import no.digipost.exceptions.Exceptions;
import no.digipost.security.DigipostSecurity;
import no.digipost.security.InvalidState;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Predicate;

import static java.util.Optional.empty;
import static no.digipost.security.DigipostSecurity.asStream;

public final class ReviewedCertPath {

    private final Optional<CertPath> path;
    private final Predicate<CertPath> isTrusted;

    public final Optional<GeneralSecurityException> exception;

    ReviewedCertPath(CertPath path, Predicate<CertPath> trusted) {
        this(Optional.of(path), trusted, empty());
    }

    ReviewedCertPath(GeneralSecurityException exception) {
        this(empty(), p -> false, Optional.of(exception));
    }

    private ReviewedCertPath(Optional<CertPath> path, Predicate<CertPath> trusted, Optional<GeneralSecurityException> exception) {
        this.path = path;
        this.isTrusted = trusted;
        this.exception = exception;
    }


    public CertPath getPath() {
        return path.orElseThrow(() -> exception.map(Exceptions::asUnchecked).get());
    }

    public boolean isTrusted() {
        return path.filter(isTrusted).isPresent();
    }

    public CertPath getTrustedPath() {
        CertPath certpath = getPath();
        if (isTrusted()) return certpath;
        throw new Untrusted(certpath, exception.orElse(null));
    }

    public TrustedCertificateAndIssuer getTrustedCertificateAndIssuer() {
        CertPath trustedCertPath = getTrustedPath();
        X509Certificate certificate = asStream(trustedCertPath).findFirst()
                .orElseThrow(() -> new InvalidState("No certificate found at all in supposedly trusted CertPath!", trustedCertPath));
        X509Certificate issuer = asStream(trustedCertPath).skip(1).findFirst()
                .orElseThrow(() -> new InvalidState("No issuer found for supposedly trusted certificate", certificate));
        return new TrustedCertificateAndIssuer(certificate, issuer);
    }

    @Override
    public String toString() {
        return new StringBuilder(isTrusted() ? "Trusted: " : "Untrusted: ")
            .append(path.map(DigipostSecurity::describe).orElse(exception.map(Exceptions::exceptionNameAndMessage).orElse("No certpath or exception")))
            .toString();
    }

}
