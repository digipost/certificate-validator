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
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.lang.reflect.Modifier.isStatic;
import static java.time.ZoneOffset.UTC;
import static java.time.format.DateTimeFormatter.ISO_LOCAL_DATE;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toCollection;
import static no.digipost.DiggExceptions.getUnchecked;
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

    @Disabled @Test
    void describeCertificate() {
        for (StaticMethod<X509Certificate> certMethod : allStaticCertifcateMethodsOf(ProdEnvCertificates.class)) {
            X509Certificate certificate = certMethod.invoke();
            System.out.println(
                    " **  " + certMethod.getName() + ":\n" + certificate.getSubjectDN() + "\n" +
                    "valid " + ISO_LOCAL_DATE.format(certificate.getNotBefore().toInstant().atZone(UTC)) +
                    " to " + ISO_LOCAL_DATE.format(certificate.getNotAfter().toInstant().atZone(UTC)) + "\n");
        }
    }


    private static void allCertificatesAreResolved(Class<?> x509CertClass) {
        Set<StaticMethod<X509Certificate>> certificateMethods = allStaticCertifcateMethodsOf(x509CertClass);

        assertThat("there are methods returning certificate in " + x509CertClass.getSimpleName(), certificateMethods, not(empty()));
        assertAll(certificateMethods.stream()
                .map(certificateMethod -> assertDoesNotThrow(() -> certificateMethod.invoke()))
                .map(resolvedCertificate -> () -> assertNotNull(resolvedCertificate)));
    }

    private static Set<StaticMethod<X509Certificate>> allStaticCertifcateMethodsOf(Class<?> x509CertClass) {
        return Stream.of(x509CertClass.getMethods())
                .map(method -> StaticMethod.ifApplicable(method, X509Certificate.class))
                .flatMap(staticMethod -> Stream.of(staticMethod).filter(Optional::isPresent).map(Optional::get))
                .sorted(comparing(StaticMethod::getName))
                .collect(toCollection(LinkedHashSet::new));
    }

    private static class StaticMethod<R> {
        public static <R> Optional<StaticMethod<R>> ifApplicable(Method methodCandidate, Class<R> returnType) {
            if (isStatic(methodCandidate.getModifiers()) && returnType.isAssignableFrom(methodCandidate.getReturnType())) {
                return Optional.of(new StaticMethod<>(methodCandidate));
            } else {
                return Optional.empty();
            }
        }

        private final Method method;

        private StaticMethod(Method staticMethod) {
            this.method = staticMethod;
        }

        R invoke(Object ... args) {
            @SuppressWarnings("unchecked")
            R returnedValue = (R) getUnchecked(() -> method.invoke(method.getDeclaringClass(), args));
            return returnedValue;
        }

        @Override
        public String toString() {
            return method.toString();
        }

        public String getName() {
            return method.getName();
        }
    }

}
