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
package no.digipost.security.ocsp;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.operator.DigestCalculator;

import java.io.OutputStream;

final class Sha1Calculator implements DigestCalculator {

    private final DigestOutputStream ouz = new DigestOutputStream(new SHA1Digest());

    @Override
    public OutputStream getOutputStream() {
        return ouz;
    }

    @Override
    public byte[] getDigest() {
        return ouz.getDigest();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return CertificateID.HASH_SHA1;
    }
}
