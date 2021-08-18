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

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.lang.reflect.Modifier.isStatic;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toSet;
import static no.digipost.security.DigipostSecurity.describe;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertificatesTest {

    @Test
    void allProdCertificatesAreResolved() {
        allCertificatesAreResolved(ProdEnvCertificates.class);
    }

    @Test
    void allTestEnvironmentCertificatesAreResolved() {
        allCertificatesAreResolved(TestEnvCertificates.class);
    }

    private static void allCertificatesAreResolved(Class<?> x509CertClass) {
        Set<Method> certificateMethods = Stream.of(x509CertClass.getMethods())
            .filter(method -> isStatic(method.getModifiers()))
            .filter(method -> X509Certificate.class.isAssignableFrom(method.getReturnType()))
            .collect(toSet());

        assertThat("there are methods returning certificate in " + x509CertClass.getSimpleName(), certificateMethods, not(empty()));
        assertAll(certificateMethods.stream()
            .map(method -> assertDoesNotThrow(() -> method.invoke(x509CertClass)))
            .map(resolvedCertificate -> () -> assertNotNull(resolvedCertificate)));
    }

    @Disabled @Test
    void describeCertificate() {
        List<X509Certificate> certs = asList(
                TestEnvCertificates.buypassClass3TestRootCaG2Psd2QWAC(),
                TestEnvCertificates.buypassClass3TestRootCaG2SoftToken(),
                TestEnvCertificates.buypassClass3TestRootCaG2HardToken());

        for (X509Certificate cert : certs) {
            System.out.println(describe(cert));
        }
    }


}
