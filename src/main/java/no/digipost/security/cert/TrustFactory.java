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

import java.time.Clock;

import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3Ca3;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3CaG2HardToken;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3CaG2SoftToken;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3RootCa;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3RootCaG2HardToken;
import static no.digipost.security.cert.ProdEnvCertificates.buypassClass3RootCaG2SoftToken;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesCa;
import static no.digipost.security.cert.ProdEnvCertificates.commfidesRootCa;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3Test4Ca3;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3Test4RootCa;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestCaG2HardToken;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestCaG2SoftToken;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestRootCaG2HardToken;
import static no.digipost.security.cert.TestEnvCertificates.buypassClass3TestRootCaG2SoftToken;
import static no.digipost.security.cert.TestEnvCertificates.commfidesTestCa;
import static no.digipost.security.cert.TestEnvCertificates.commfidesTestRootCa;

public final class TrustFactory {

    public final Seid1 seid1;
    public final Seid2 seid2;
    private final Clock clock;

    public TrustFactory(Clock clock) {
        this.seid1 = new Seid1();
        this.seid2 = new Seid2();
        this.clock = clock;
    }


    /**
     * SEID 2.0 is the Norwegian standard for certificates aligning with the
     * European eIDAS standard.
     */
    public final class Seid2 {

        public Trust buypassEnterpriseCertificates() {
            return Trust.from(clock,
                    buypassClass3RootCaG2SoftToken(), buypassClass3CaG2SoftToken(),
                    buypassClass3RootCaG2HardToken(), buypassClass3CaG2HardToken());
        }

        public Trust buypassTestEnterpriseCertificates() {
            return Trust.from(clock,
                    buypassClass3TestRootCaG2SoftToken(), buypassClass3TestCaG2SoftToken(),
                    buypassClass3TestRootCaG2HardToken(), buypassClass3TestCaG2HardToken());
        }

        private Seid2() {
        }
    }



    /**
     * SEID 1.0 is a Norwegian standard for certificates, which is
     * currently being phased out, and to be replaced by {@link Seid2 SEID 2.0}.
     */
    public final class Seid1 {

        public Trust buypassAndCommfidesEnterpriseCertificates() {
            return Trust.merge(buypassEnterpriseCertificates(), commfidesEnterpriseCertificates());
        }

        public Trust buypassAndCommfidesTestEnterpriseCertificates() {
            return Trust.merge(buypassTestEnterpriseCertificates(), commfidesTestEnterpriseCertificates());
        }

        public Trust buypassEnterpriseCertificates() {
            return Trust.from(clock, buypassClass3RootCa(), buypassClass3Ca3());
        }

        public Trust buypassTestEnterpriseCertificates() {
            return Trust.from(clock, buypassClass3Test4RootCa(), buypassClass3Test4Ca3());
        }

        public Trust commfidesEnterpriseCertificates() {
            return Trust.from(clock, commfidesRootCa(), commfidesCa());
        }

        public Trust commfidesTestEnterpriseCertificates() {
            return Trust.from(clock, commfidesTestRootCa(), commfidesTestCa());
        }

        private Seid1() {
        }
    }


}
