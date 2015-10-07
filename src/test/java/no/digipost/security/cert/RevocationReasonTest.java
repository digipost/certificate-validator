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

import com.pholser.junit.quickcheck.ForAll;
import no.digipost.security.cert.RevocationReason;
import org.junit.contrib.theories.Theories;
import org.junit.contrib.theories.Theory;
import org.junit.runner.RunWith;

import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static no.digipost.security.cert.RevocationReason.UNKNOWN;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeThat;

@RunWith(Theories.class)
public class RevocationReasonTest {

    @Theory
    public void managesToResolveAnyReason(@ForAll int code) {
        assertThat(RevocationReason.resolve(code), notNullValue());
    }

    @Theory
    public void resolveParticularReason(@ForAll RevocationReason reason) {
        assertThat(RevocationReason.resolve(reason.code), sameInstance(reason));
    }

    @Theory
    public void unknownReasonCodes(@ForAll int unknownCode) {
        assumeThat(unknownCode, not(isIn(Stream.of(RevocationReason.values()).filter(r -> r != UNKNOWN).map(r -> r.code).collect(toList()))));
        assertThat(RevocationReason.resolve(unknownCode), is(UNKNOWN));
    }


}
