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
package no.digipost.security.cert;

import no.digipost.security.DigipostSecurity;
import no.digipost.security.InvalidState;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Iterator;
import java.util.stream.Stream;

import static no.digipost.security.DigipostSecurity.asCertPath;
import static no.digipost.security.DigipostSecurity.readCertificates;
import static no.digipost.security.cert.CertificatesForTesting.digipostVirksomhetssertifikat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static uk.co.probablyfine.matchers.Java8Matchers.where;
import static uk.co.probablyfine.matchers.Java8Matchers.whereNot;

public class ReviewedCertPathTest {

    @Test
    public void exceptionIsUntrusted() {
        ReviewedCertPath certPath = new ReviewedCertPath(new GeneralSecurityException());
        assertThat(certPath, whereNot(ReviewedCertPath::isTrusted));
    }

    @Test
    public void nullCertificateIsNotAllowed() {
        assertThrows(NullPointerException.class, () -> new ReviewedCertPath(null, p -> true));
    }

    @Test
    public void trustedCertificate() {
        CertPath certpath = mock(CertPath.class);
        ReviewedCertPath reviewedPath = new ReviewedCertPath(certpath, p -> true);
        assertThat(reviewedPath, where(ReviewedCertPath::isTrusted));
        assertThat(reviewedPath, where(ReviewedCertPath::getTrustedPath, sameInstance(certpath)));
    }

    @Test
    public void untrustedCertificate() {
        assertThat(new ReviewedCertPath(mock(CertPath.class), p -> false), whereNot(ReviewedCertPath::isTrusted));
    }

    @Test
    public void cannotExtractCertificateAndIssuerWhenUntrusted() {
        CertPath certpath = asCertPath(DigipostSecurity.readCertificates("digipost.no-certchain.pem"));
        ReviewedCertPath reviewedCertPath = new ReviewedCertPath(certpath, c -> false);

        assertThrows(Untrusted.class, () -> reviewedCertPath.getTrustedCertificateAndIssuer());
    }

    @Test
    public void extractsCertificateAndIssuerWhenTrusted() {
        CertPath certpath = asCertPath(readCertificates("digipost.no-certchain.pem"));
        ReviewedCertPath reviewedCertPath = new ReviewedCertPath(certpath, c -> true);

        Iterator<? extends Certificate> certsInPath = certpath.getCertificates().iterator();
        TrustedCertificateAndIssuer certAndIssuer = reviewedCertPath.getTrustedCertificateAndIssuer();
        assertThat(certAndIssuer.certificate, is(certsInPath.next()));
        assertThat(certAndIssuer.issuer, is(certsInPath.next()));
    }

    @Test
    public void trustingCertificatePathWithOnlyOneCertificateIsInvalid() {
        CertPath certpath = asCertPath(Stream.of(digipostVirksomhetssertifikat()));
        ReviewedCertPath reviewedCertPath = new ReviewedCertPath(certpath, c -> true);

        InvalidState thrown = assertThrows(InvalidState.class, () -> reviewedCertPath.getTrustedCertificateAndIssuer());
        assertThat(thrown, where(Exception::getMessage, containsString("No issuer found")));
    }

    @Test
    public void trustingCertificatePathWithNocertificatesIsObviouslyInvalid() {
        CertPath certpath = mock(CertPath.class);
        ReviewedCertPath reviewedCertPath = new ReviewedCertPath(certpath, c -> true);

        InvalidState thrown = assertThrows(InvalidState.class, reviewedCertPath::getTrustedCertificateAndIssuer);
        assertThat(thrown, where(Exception::getMessage, containsString("No certificate found")));
    }

    @Test
    public void toStringForTrustedCertPath() {
        CertPath certPath = asCertPath(Stream.of(digipostVirksomhetssertifikat()));
        String description = new ReviewedCertPath(certPath, c -> true).toString();
        assertThat(description, is("Trusted: " + DigipostSecurity.describe(certPath)));
    }

    @Test
    public void toStringForUntrustedCertPath() {
        CertPath certPath = asCertPath(Stream.of(CertificatesForTesting.digipostVirksomhetssertifikat()));
        String description = new ReviewedCertPath(certPath, c -> false).toString();
        assertThat(description, is("Untrusted: " + DigipostSecurity.describe(certPath)));
    }

    @Test
    public void toStringForException() {
        CertificateParsingException exception = new CertificateParsingException("bogus certificate");
        String description = new ReviewedCertPath(exception).toString();
        assertThat(description, is("Untrusted: " + CertificateParsingException.class.getSimpleName() + ": 'bogus certificate'"));
    }

}
