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

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * The basic constraints extension (OID {@value BasicConstraints#OID}) identifies whether the subject of the
 * certificate is a CA and the maximum depth of valid certification
 * paths that include this certificate.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc3280.html#section-4.2.1.10">
 *         https://datatracker.ietf.org/doc/html/rfc3280.html#section-4.2.1.10
 *      </a>
 */
public final class BasicConstraints {

    public static final String OID = "2.5.29.19";

    public enum Type {
        /**
         * Certificate Authority
         */
        CA,

        /**
         * Not a {@link #CA}, i.e. typically an end entity (EE) certificate
         */
        NON_CA,

        /**
         * The basic constraints extension could not be resolved, so it is unknown
         */
        UNKNOWN
    }

    public static BasicConstraints from(X509Certificate certificate) {
        if (certificate.getExtensionValue(BasicConstraints.OID) != null) {
            int pathLenConstraint = certificate.getBasicConstraints();
            return new BasicConstraints(pathLenConstraint >= 0 ? Type.CA : Type.NON_CA, pathLenConstraint);
        } else {
            return new BasicConstraints(Type.UNKNOWN, -1);
        }
    }


    public final Type type;

    /**
     * The {@code pathLenConstraint} value of the basic constraints.
     * This value is only meaningful in the case that {@link #type} == {@link Type#CA},
     * and gives the maximum number of non-self-issued intermediate certificates
     * that may follow this certificate in a valid certification path.
     * <p>Note: The last certificate in the certification path is not an
     * intermediate certificate, and is not included in this limit.
     * A {@code maxFollowingIntermediateCerts} of <em>zero</em> indicates that
     * <em>only one more certificate may follow in a valid certification path</em>.
     */
    public final int maxFollowingIntermediateCerts;

    public BasicConstraints(Type type, int maxFollowingPathLength) {
        this.type = type;
        this.maxFollowingIntermediateCerts = maxFollowingPathLength;
    }


    @Override
    public boolean equals(Object other) {
        if (other instanceof BasicConstraints) {
            BasicConstraints that = (BasicConstraints) other;
            if (this.type == Type.CA) {
                return this.type == that.type && this.maxFollowingIntermediateCerts == that.maxFollowingIntermediateCerts;
            } else {
                return this.type == that.type;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        if (this.type == Type.CA) {
            hash = 31 * hash + Integer.hashCode(maxFollowingIntermediateCerts);
        }
        hash = 31 * hash + Objects.hashCode(type);
        return hash;
    }

    @Override
    public String toString() {
        return "BasicConstraints OID " + OID + ": " + type + ", " +
               "maxFollowingIntermediateCerts: " + (type != Type.CA ? "(not applicable) " : "") + maxFollowingIntermediateCerts;
    }

}
