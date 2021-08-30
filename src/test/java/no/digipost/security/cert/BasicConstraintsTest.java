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

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.jupiter.api.Test;

import static no.digipost.security.cert.BasicConstraints.Type.CA;
import static no.digipost.security.cert.BasicConstraints.Type.NON_CA;
import static no.digipost.security.cert.BasicConstraints.Type.UNKNOWN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static uk.co.probablyfine.matchers.Java8Matchers.where;

class BasicConstraintsTest {

    @Test
    void equalsAndHashCodeDisregardsMaxFollowingIntermediateCertsValueForNonCaAndUnknown() {
        EqualsVerifier
            .forRelaxedEqualExamples(new BasicConstraints(UNKNOWN, -1), new BasicConstraints(UNKNOWN, 0), new BasicConstraints(UNKNOWN, 1))
            .andUnequalExamples(new BasicConstraints(NON_CA, -1), new BasicConstraints(CA, 1), new BasicConstraints(CA, 2))
            .verify();

        EqualsVerifier
            .forRelaxedEqualExamples(new BasicConstraints(NON_CA, -1), new BasicConstraints(NON_CA, 0), new BasicConstraints(NON_CA, 1))
            .andUnequalExamples(new BasicConstraints(UNKNOWN, -1), new BasicConstraints(CA, 1), new BasicConstraints(CA, 2))
            .verify();
    }

    @Test
    void detectsCaCertificate() {
        BasicConstraints issuerBasicConstraints = BasicConstraints.from(CertificatesForTesting.BUYPASS_SEID_2_ISSUER);
        assertThat(issuerBasicConstraints, where(bc -> bc.type, is(CA)));
    }

    @Test
    void detectsNonCaCertificate() {
        BasicConstraints basicConstraints = BasicConstraints.from(CertificatesForTesting.BUYPASS_SEID_2_CERT);
        assertThat(basicConstraints, where(bc -> bc.type, is(NON_CA)));
    }

}
