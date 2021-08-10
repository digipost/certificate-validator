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
import no.digipost.security.HttpClient;
import org.apache.http.HttpHost;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static no.digipost.security.cert.CertStatus.OK;
import static no.digipost.security.cert.CertStatus.UNDECIDED;
import static no.digipost.security.cert.CertStatus.UNTRUSTED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@SuppressWarnings("unused")
public class RealOCSPCertificateValidatorTest {

    private static final Optional<HttpHost> proxy =  Optional.ofNullable(System.getProperty("https_proxy")).map(HttpHost::create);
    private static final CertificateValidator validator = new CertificateValidator(BuypassCommfidesCertificates.createProdTrust(), HttpClient.create(proxy));


    @Test
    public void validerer_gammelt_commfides_sertifikat() {
        X509Certificate commfidesSert = DigipostSecurity.readCertificate(GAMMELT_COMMFIDES_SERTIFIKAT_KS.getBytes());

        assertThat("Untrusted pga ocsp-response signert med utdatert sertifikat",
                   validator.validateCert(commfidesSert), is(UNTRUSTED));
    }

    @Test
    public void unknown_ocsprespone_gir_undecided_for_nytt_commfides_sertifikat() {
        X509Certificate commfidesSert = NYTT_COMMFIDES_SERTIFIKAT_KS;

        assertThat(validator.validateCert(commfidesSert), is(UNDECIDED));
    }

    @Test
    public void godtar_nytt_commfides_test_sertifikat() {
        CertificateValidator validatorQaEnv = new CertificateValidator(
                CertificateValidatorConfig.MOST_STRICT.allowOcspResults(UNDECIDED),
                BuypassCommfidesCertificates.createTestTrust(),
                HttpClient.create());

        assertThat(validatorQaEnv.validateCert(EBOKS_COMMFIDES_TEST), is(OK));
    }


    @Test
    public void validerer_nytt_buypass_sertifikat() {
        X509Certificate buypassSert = DigipostSecurity.readCertificate(BUYPASS_MF_PROD_SERTIFIKAT.getBytes());

        assertThat(validator.validateCert(buypassSert), is(OK));
    }

    private static final X509Certificate EBOKS_COMMFIDES_TEST = DigipostSecurity.readCertificate((
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIGgDCCBWigAwIBAgIIXWattKnFcDswDQYJKoZIhvcNAQELBQAwgfMxPTA7BgNV\n" +
            "BAMTNENvbW1maWRlcyBDUE4gRW50ZXJwcmlzZS1Ob3J3ZWdpYW4gU0hBMjU2IENB\n" +
            "IC0gVEVTVDIxRjBEBgNVBAsTPUNvbW1maWRlcyBUcnVzdCBFbnZpcm9ubWVudChD\n" +
            "KSAyMDE0IENvbW1maWRlcyBOb3JnZSBBUyAtIFRFU1QxMjAwBgNVBAsTKUNQTiBF\n" +
            "bnRlcnByaXNlLU5vcndlZ2lhbiBTSEEyNTYgQ0EtIFRFU1QyMSkwJwYDVQQKEyBD\n" +
            "b21tZmlkZXMgTm9yZ2UgQVMgLSA5ODggMzEyIDQ5NTELMAkGA1UEBhMCTk8wHhcN\n" +
            "MTQxMDE3MTM0NDAwWhcNMjIxMDAzMTI1MzQ0WjCB1jEYMBYGA1UEAxMPVGVzdCBW\n" +
            "aXJrc29taGV0MRIwEAYDVQQFEwk5NTg5MzU0MjAxGDAWBgNVBAsTD1Rlc3QgU2Vy\n" +
            "dGlmaWthdDFCMEAGA1UECxM5SXNzdWVkIEJ5IENvbW1maWRlcyBFbnRlcnByaXNl\n" +
            "IE5vcndlZ2lhbiBTSEEyNTYgQ0EgLSBURVNUMRgwFgYDVQQKEw9UZXN0IFZpcmtz\n" +
            "b21oZXQxEDAOBgNVBAcTB0x5c2FrZXIxDzANBgNVBAgMBkLDpnJ1bTELMAkGA1UE\n" +
            "BhMCTk8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4A4rRbK97GFvB\n" +
            "IourESPHYyKvJtrsdogl7Uvi5PNHHk32Vyi7GxoPGJeQBtBx4T2u1UPlBZAq6c7c\n" +
            "RA3PAz+yKDQEiDRqaE4clRNRcyqMbQbB802DJzHJQITfE/HzJfH/70PN1a9QnL7N\n" +
            "GFkJYlBLejQ470A7+CXoabIasHoxi7zw/ESdNxtSWL9GF+cw6rXiQdCLKzE2d0BB\n" +
            "Y4n9zIjv+pqVPcQqzl5ScycN52Abqps2WmgZpG9SEm85EsrzUZkyOB0Qnu46OuU8\n" +
            "qZMP1wQ2uYm0kRMVmBFzSNxviq2Hi9Pjnx6WJ11uS2u4Le7pXfHbWnMnHZ/2PqU8\n" +
            "kn3V6GK7AgMBAAGjggIxMIICLTCB2AYIKwYBBQUHAQEEgcswgcgwSQYIKwYBBQUH\n" +
            "MAKGPWh0dHA6Ly9jcmwxLnRlc3QuY29tbWZpZGVzLmNvbS9Db21tZmlkZXNFbnRl\n" +
            "cnByaXNlLVNIQTI1Ni5jcnQwSQYIKwYBBQUHMAKGPWh0dHA6Ly9jcmwyLnRlc3Qu\n" +
            "Y29tbWZpZGVzLmNvbS9Db21tZmlkZXNFbnRlcnByaXNlLVNIQTI1Ni5jcnQwMAYI\n" +
            "KwYBBQUHMAGGJGh0dHA6Ly9vY3NwMS50ZXN0LmNvbW1maWRlcy5jb20vb2NzcDAd\n" +
            "BgNVHQ4EFgQUqknwms5U+6xLpIQHZO+tllv2L3QwDAYDVR0TAQH/BAIwADAfBgNV\n" +
            "HSMEGDAWgBREMe/Jvu3pYo2fhCBNSoXKflRwVjAXBgNVHSAEEDAOMAwGCmCEQgEd\n" +
            "hxEBAQAwgZYGA1UdHwSBjjCBizBDoEGgP4Y9aHR0cDovL2NybDEudGVzdC5jb21t\n" +
            "ZmlkZXMuY29tL0NvbW1maWRlc0VudGVycHJpc2UtU0hBMjU2LmNybDBEoEKgQIY+\n" +
            "aHR0cDovL2NybDIudGVzdC5jb21tZmlkZXMuY29tL0NvbW1maWRlc0VudGVycHJp\n" +
            "c2UyLVNIQTI1Ni5jcmwwDgYDVR0PAQH/BAQDAgeAMCcGA1UdJQQgMB4GCCsGAQUF\n" +
            "BwMBBggrBgEFBQcDAgYIKwYBBQUHAwQwFwYDVR0RBBAwDoEMcG9zdEB0ZXN0Lm5v\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQAfNsIsocJE7ParF3ZI2950In8yshiafVKLdbdl\n" +
            "tELS6YVUDaBq6BckzhqSt6hDmx4GLC+f0lIvUKh/cN8XpCw+CsvoHmzqlX8xTPIo\n" +
            "WlnDydoeIPuP6XyQVtvcdZCuDUlOyLWkQqqhC+yrAJ3M9T7xcuX79EEp05YU8p/g\n" +
            "Ea8Fcn4Y6H+Ef4kbsWsrtTXJiXRWFywt8vFJSoEdJRRAZHz+x7JYubCSaZugwAAA\n" +
            "RtlGQ25hKNhpVTmvPjclm1QEy6FXOVesowVoYLvzX93x88HWMFnDJnLoBm3SpZ1U\n" +
            "Bc6vWn44lPAXyrr1byDp/R69H4/lVrlJU23SPgY3i9ksErmL\n" +
            "-----END CERTIFICATE-----").getBytes());


    private static final X509Certificate NYTT_COMMFIDES_SERTIFIKAT_KS = DigipostSecurity.readCertificate((
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIGNTCCBR2gAwIBAgIIGYwAMkW8DVUwDQYJKoZIhvcNAQELBQAwgaIxJjAkBgNV\n" +
            "BAMTHUNQTiBFbnRlcnByaXNlIFNIQTI1NiBDTEFTUyAzMUAwPgYDVQQLEzdDb21t\n" +
            "ZmlkZXMgVHJ1c3QgRW52aXJvbm1lbnQgKGMpIDIwMTEgQ29tbWZpZGVzIE5vcmdl\n" +
            "IEFTMSkwJwYDVQQKEyBDb21tZmlkZXMgTm9yZ2UgQVMgLSA5ODggMzEyIDQ5NTEL\n" +
            "MAkGA1UEBhMCTk8wHhcNMTUwNjA1MTAxNjIwWhcNMjQxMjMxMTM0ODM5WjCBkjEL\n" +
            "MAkGA1UEAxMCS1MxEjAQBgNVBAUTCTk3MTAzMjE0NjEcMBoGA1UECxMTQXZkLiBE\n" +
            "aWdpdGFsaXNlcmluZzEXMBUGA1UEChMOS1MgLSA5NzEwMzIxNDYxKzApBgNVBAcT\n" +
            "IkhBQUtPTiBWSUlTR1QgOSwgMDE2MSwgT1NMTywgTm9yZ2UxCzAJBgNVBAYTAk5P\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvK3nVKRDUnRq3EzAoNuO\n" +
            "Q/Ba5EYwq40Jwh2viT0FVNT/AU1qqZTD+EZxUWeEi8NiEj/OP3mEdQ90g0h36Q12\n" +
            "C4NnDbRsE567k1gjsqoLsgzuYnH6JoklTl1M9FRGW0XwlJZUt813FmwoBMDDpDBL\n" +
            "ZAvSPPItttKXhGavjHjFuYVHbJgn4W/A+Hpca9DrdZfQwhWw5zzmR151jfYYKkqb\n" +
            "hDvzXDINTZG7zK8h1HA4H+8XPdkpdtDU3Z1GgGqzmlU8K8Sb6tm0sR4Pb4iGnDuz\n" +
            "ow51hN0eWQ5SmtpqVeyAAFp2D2uEJ5sGZvLSnnMjJ+G4B2tkqavL/IGFKS1JGCNC\n" +
            "iwIDAQABo4ICezCCAncwgckGCCsGAQUFBwEBBIG8MIG5MEQGCCsGAQUFBzAChjho\n" +
            "dHRwOi8vY3JsMS5jb21tZmlkZXMuY29tL0NvbW1maWRlc0VudGVycHJpc2UtU0hB\n" +
            "MjU2LmNydDBEBggrBgEFBQcwAoY4aHR0cDovL2NybDIuY29tbWZpZGVzLmNvbS9D\n" +
            "b21tZmlkZXNFbnRlcnByaXNlLVNIQTI1Ni5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6\n" +
            "Ly9vY3NwMS5jb21tZmlkZXMuY29tL29jc3AwHQYDVR0OBBYEFNxrSqT5ErDfVOun\n" +
            "pjGFEzuYahKBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUks2AHB7BuXk8taiD\n" +
            "kshciI1IzrkwFgYDVR0gBA8wDTALBglghEIBHQ0BAQAwgeQGA1UdHwSB3DCB2TCB\n" +
            "lqA8oDqGOGh0dHA6Ly9jcmwxLmNvbW1maWRlcy5jb20vQ29tbWZpZGVzRW50ZXJw\n" +
            "cmlzZS1TSEEyNTYuY3JsolakVDBSMSYwJAYDVQQDDB1DUE4gRW50ZXJwcmlzZSBT\n" +
            "SEEyNTYgQ0xBU1MgMzEbMBkGA1UECgwSQ29tbWZpZGVzIE5vcmdlIEFTMQswCQYD\n" +
            "VQQGEwJOTzA+oDygOoY4aHR0cDovL2NybDIuY29tbWZpZGVzLmNvbS9Db21tZmlk\n" +
            "ZXNFbnRlcnByaXNlLVNIQTI1Ni5jcmwwDgYDVR0PAQH/BAQDAgM4MDMGA1UdJQQs\n" +
            "MCoGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwQwFwYD\n" +
            "VR0RBBAwDoEMc3ZhcnV0QGtzLm5vMA0GCSqGSIb3DQEBCwUAA4IBAQBvm5ctcde4\n" +
            "3a6Ni5AExO3xU0JoMU4MfIUPYL7Ey996qTpqMDlA/AB9UXG21ClTONmLrh4HuBPo\n" +
            "OR0mZ1jLeU3car4z64m+4GqhuUEQAn9+Jj5v9F5OZKnm0SzOf8h/Si+0bD4Eu/R5\n" +
            "bqQgw+qKAbXNjOHoECUgRSdsHArks8+I+5iwFR4IU/HvQZUco2HpKZNG6vYgCTLX\n" +
            "iM1oPOH4lYHh0/S7fy1ZPKCcwOjBQ4R23oIyhlNYt5hmuisZuzLB0yYcaJiOoqRV\n" +
            "8OhEqOTRbA0T2BkqrYcJxNV9ZU1ycKoWzNGZ+gPWEsbO9f+LYaBzmBCu4L3U8vb1\n" +
            "5dnJtwMyzNeI\n" +
            "-----END CERTIFICATE-----").getBytes());



    private static final String GAMMELT_COMMFIDES_SERTIFIKAT_KS =
                    "-----BEGIN CERTIFICATE-----\n" +
                    "MIIGszCCBJugAwIBAgIIXZiEOEOjCnYwDQYJKoZIhvcNAQEFBQAwgeMxLjAsBgNV\n" +
                    "BAMTJUNvbW1maWRlcyBDUE4gRW50ZXJwcmlzZSBOb3J3ZWdpYW4gQ0ExQDA+BgNV\n" +
                    "BAsTN0NvbW1maWRlcyBUcnVzdCBFbnZpcm9ubWVudCAoQykgMjAwNiBDb21tZmlk\n" +
                    "ZXMgTm9yZ2UgQVMxNzA1BgNVBAsTLkNQTiBFbnRlcnByaXNlIE5vcndlZ2lhbiBD\n" +
                    "ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxKTAnBgNVBAoTIENvbW1maWRlcyBOb3JnZSBB\n" +
                    "UyAtIDk4OCAzMTIgNDk1MQswCQYDVQQGEwJOTzAeFw0xMzA5MDQwOTEzNDhaFw0x\n" +
                    "ODA5MTYwOTEzNDhaMIIBBDEbMBkGCSqGSIb3DQEJARYMc3ZhcnV0QGtzLm5vMQsw\n" +
                    "CQYDVQQDEwJLUzESMBAGA1UEBRMJOTcxMDMyMTQ2MUAwPgYDVQQLEzdTQU1MIFNp\n" +
                    "Z25pbmcsIEF1dGhlbnRpY2F0aW9uIGFuZCBFbmNyeXB0aW9uIENlcnRpZmljYXRl\n" +
                    "MTQwMgYDVQQLEytJc3N1ZWQgYnkgQ29tbWZpZGVzIEVudGVycHJpc2UgTm9yd2Vn\n" +
                    "aWFuIENBMQswCQYDVQQKEwJLUzEjMCEGA1UEBxMaSEFBS09OIFZJSVNHVCA5LCAw\n" +
                    "MTYxIE9TTE8xDTALBgNVBAgTBE9TTE8xCzAJBgNVBAYTAk5PMIIBIjANBgkqhkiG\n" +
                    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgPaFoAi97p4b27Kn8RDc1jl3r2FhmR+oh1nG\n" +
                    "sFoFUSxujMU7p8kCUj/eD5cPIc3RUkzuvZ5/gZR2NHsCRvSdo3GRUZ9nIWp5wna7\n" +
                    "rRf+68xRXiCdSSSfqvcwlni4tEzmwLIV4C5KCHT+yUz7sL+5o0G0HINS1S7eLTl5\n" +
                    "nn54R1UPLfhe7UBVuD0JlZGDL2hLtH0y+E3I5XpuUIl/C6Du12pMxLl86XYnrlmr\n" +
                    "O10+Ri90ossjruVuM8e7W+6Y5YQ1717fU5d58rOFW54djYbaFjxENTkb3sw1DRyG\n" +
                    "ixu/mcbLRJrPwT/jFovR3fpOUIEbwfgy0MfNuoeVbFaDaMdMBQIDAQABo4IBRTCC\n" +
                    "AUEwDAYDVR0TAQH/BAIwADAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIG\n" +
                    "CCsGAQUFBwMEMB8GA1UdIwQYMBaAFNNJ72b2UBYDRQMuOu9709G78y4xMEsGA1Ud\n" +
                    "HwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuY29tbWZpZGVzLmNvbS9Db21tZmlkZXNF\n" +
                    "bnRlcnByaXNlLU5vcndlZ2lhbi5jcmwwDgYDVR0PAQH/BAQDAgP4MB0GA1UdDgQW\n" +
                    "BBRPMKOezbW76H1bdTyfUF7d/prpszAWBgNVHSAEDzANMAsGCWCEQgEdAwEBATA6\n" +
                    "BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLmNvbW1maWRl\n" +
                    "cy5jb20vb2NzcDAXBgNVHREEEDAOgQxzdmFydXRAa3Mubm8wDQYJKoZIhvcNAQEF\n" +
                    "BQADggIBADVj49uGs6WiRo3lUEOa4VvEwlwO9In9xzoMfqb4N7rgEXtEBvYSSDWz\n" +
                    "8WQn1Yp7yt1mZsNl6BulfTi/CpB3W8w2nGz6Ru6dQjJaEn/4Gf063lK231DE7PFi\n" +
                    "fiYcOnLsA9t6pzlkivZ6zM7ZN5TgoKmYshKt+2xlyhDIV+7V/c7I/xi7FeylUlko\n" +
                    "AuN8RIAT03gwjaXczeaKhJSBLD4U5dSrSDPPyvy+WB2pDNRN84gJ1RcXJpoJ0zIU\n" +
                    "Ff7fN7yPLQ17V6XsHd+x6xoZm4pogvvOk6sS0FlQlAB9l8gF85dERKrHU6uxBAXU\n" +
                    "3rmOhGBK1oHkYg+BUTcgVjy4bjG4MIBv/hIIeH/MpMKGAuM0X2UwuPORWa8IjTOs\n" +
                    "GIAmUN6YqgUjgYHgic1BmLX1RcYq4C+impLbxIUIY60GW4uqi0tzna1XZpvnw1/M\n" +
                    "eD5O5wc8TgqF4IFun3TIej0QoqZsWbbtQqUreRJbVxCkKm7JSwu9lPkF/ICYXhXL\n" +
                    "23YJFFXvVAS4cl0yKOWfu0GAj89ySPqKR4jiCDgwo8/1dS60xzv3U7eE2B2a8Iee\n" +
                    "nsJiezqLb33WQbhvyT5paNXtRw4SsT8+7233577ts1e4tt5q4wo/aeHsSjSX9LKe\n" +
                    "nCZizViRMZDueNce+J26mOi60dxJjQc8du2ZCmAyQzOcCguQANUR\n" +
                    "-----END CERTIFICATE-----";

    private static final String BUYPASS_MF_PROD_SERTIFIKAT =
                    "-----BEGIN CERTIFICATE-----\n" +
                    "MIIE1DCCA7ygAwIBAgILC0banYlr12VQNoQwDQYJKoZIhvcNAQELBQAwSzELMAkG\n" +
                    "A1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MR0wGwYDVQQD\n" +
                    "DBRCdXlwYXNzIENsYXNzIDMgQ0EgMzAeFw0xNzA2MDExMjMwMDhaFw0yMDA2MDEy\n" +
                    "MTU5MDBaMGgxCzAJBgNVBAYTAk5PMRgwFgYDVQQKDA9QT1NURU4gTk9SR0UgQVMx\n" +
                    "ETAPBgNVBAsMCERpZ2lwb3N0MRgwFgYDVQQDDA9QT1NURU4gTk9SR0UgQVMxEjAQ\n" +
                    "BgNVBAUTCTk4NDY2MTE4NTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                    "AKgYMYMfkSkPi/njmKkAhWDoNgy/5MXlfRYw02bvknbDiOTJPOQrDqSg4g5BsOuL\n" +
                    "XnjcLueNdVSiqwdt+EnDtbdE6BphDf1et2vJfDSpTrn5z7NRBmOrAKpX9V9/1H2M\n" +
                    "liSBxdMgKDACfYmPi8TBShUOWOB2JUW9u6noUdx+vB3ZjUTzaiDtPnU1gqM8E+eY\n" +
                    "KIGW6wpBdiPuBMXXGlS03bJ5ztyilqCyvpKY4I7T8XX5fR+C10avMHfHZKkscFku\n" +
                    "Ha6yY70Audr5TIXnp/sLJTgYEsKXd3UYHQg/4iZ/YpGqgZuPGUBQl7urpKvsFHWL\n" +
                    "3dERM7PMVMctAyPXTWg+HRUCAwEAAaOCAZowggGWMAkGA1UdEwQCMAAwHwYDVR0j\n" +
                    "BBgwFoAUzMP4B7ecbXpO9acrHQX5s0cckdEwHQYDVR0OBBYEFP7h5beQE8Xi8Yd8\n" +
                    "zppcYDtzSel+MA4GA1UdDwEB/wQEAwIEsDAVBgNVHSAEDjAMMAoGCGCEQgEaAQMC\n" +
                    "MIGlBgNVHR8EgZ0wgZowL6AtoCuGKWh0dHA6Ly9jcmwuYnV5cGFzcy5uby9jcmwv\n" +
                    "QlBDbGFzczNDQTMuY3JsMGegZaBjhmFsZGFwOi8vbGRhcC5idXlwYXNzLm5vL2Rj\n" +
                    "PUJ1eXBhc3MsZGM9Tk8sQ049QnV5cGFzcyUyMENsYXNzJTIwMyUyMENBJTIwMz9j\n" +
                    "ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MHoGCCsGAQUFBwEBBG4wbDAzBggrBgEF\n" +
                    "BQcwAYYnaHR0cDovL29jc3AuYnV5cGFzcy5uby9vY3NwL0JQQ2xhc3MzQ0EzMDUG\n" +
                    "CCsGAQUFBzAChilodHRwOi8vY3J0LmJ1eXBhc3Mubm8vY3J0L0JQQ2xhc3MzQ0Ez\n" +
                    "LmNlcjANBgkqhkiG9w0BAQsFAAOCAQEAcE7jlA1Y9K7tF5E3nUvrfC8amXKN8K/H\n" +
                    "joy9QJMw8pafGm/tnIoKjAR7/5Lvc2SSw6VKtKWqVr/sVHlbvHRtZe0zyyja15a/\n" +
                    "0+wiI8TRoePPLXztacb398myoZBPnJKKdQdOmIQtoRPb7lcrwFzT5TIsiliSZshA\n" +
                    "rfE1ns/o/TrcClI7FvxBbwUF0kDGSh1jkh2v26ioc+Hvs3Yxf19xspFVDPZ+01Z4\n" +
                    "0XDY2XdsA4pkeJdvieeyZ2q2RGXxLEVcftlOLm2Mgthf+fRLEKUeBsXfLqDEKpca\n" +
                    "V4WRqeRSKdtXWz6TdsDT3jazcuk1fzcFlhek6ez0JmO/ePI92s0O2w==\n" +
                    "-----END CERTIFICATE-----";

    private static final String BUYPASS_MF_TEST_SERTIFIKAT =
                    "-----BEGIN CERTIFICATE-----\n" +
                    "MIIE7jCCA9agAwIBAgIKGBj1bv99Jpi+EzANBgkqhkiG9w0BAQsFADBRMQswCQYD\n" +
                    "VQQGEwJOTzEdMBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxIzAhBgNVBAMM\n" +
                    "GkJ1eXBhc3MgQ2xhc3MgMyBUZXN0NCBDQSAzMB4XDTE0MDQyNDEyMzExMVoXDTE3\n" +
                    "MDQyNDIxNTkwMFowVTELMAkGA1UEBhMCTk8xGDAWBgNVBAoMD1BPU1RFTiBOT1JH\n" +
                    "RSBBUzEYMBYGA1UEAwwPUE9TVEVOIE5PUkdFIEFTMRIwEAYDVQQFEwk5ODQ2NjEx\n" +
                    "ODUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLTnQryf2bmiyQ9q3y\n" +
                    "lQ6xMl7EhGIbjuziXkRTfL+M94m3ceAiko+r2piefKCiquLMK4j+UDcOapUtLC4d\n" +
                    "T4c6GhRH4FIOEn5aNS2I/njTenBypWka/VEhQUj7zvIh5G4UXIDIXYvLd7gideeM\n" +
                    "tkX24KUh2XVlh+PcqLGHirqBwVfFiTn5SKhr/ojhYYEb2xxTk3AY9nLd1MMffKQw\n" +
                    "UWmfoTos4scREYGI2R2vWxKWPcDqk+jig2DISWSJSuerz3HMYAAmp+Gjt0oFJNiy\n" +
                    "OFaFyGwT3DvqwOMQWwWXdmLh1NxMgTpghXAaXae76ucm9GDQ9E7ytf+JA096RWoi\n" +
                    "+5GtAgMBAAGjggHCMIIBvjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFD+u9XgLkqNw\n" +
                    "IDVfWvr3JKBSAfBBMB0GA1UdDgQWBBTVyVLqcjWf1Qd0gsmCTrhXiWeqVDAOBgNV\n" +
                    "HQ8BAf8EBAMCBLAwFgYDVR0gBA8wDTALBglghEIBGgEAAwIwgbsGA1UdHwSBszCB\n" +
                    "sDA3oDWgM4YxaHR0cDovL2NybC50ZXN0NC5idXlwYXNzLm5vL2NybC9CUENsYXNz\n" +
                    "M1Q0Q0EzLmNybDB1oHOgcYZvbGRhcDovL2xkYXAudGVzdDQuYnV5cGFzcy5uby9k\n" +
                    "Yz1CdXlwYXNzLGRjPU5PLENOPUJ1eXBhc3MlMjBDbGFzcyUyMDMlMjBUZXN0NCUy\n" +
                    "MENBJTIwMz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MIGKBggrBgEFBQcBAQR+\n" +
                    "MHwwOwYIKwYBBQUHMAGGL2h0dHA6Ly9vY3NwLnRlc3Q0LmJ1eXBhc3Mubm8vb2Nz\n" +
                    "cC9CUENsYXNzM1Q0Q0EzMD0GCCsGAQUFBzAChjFodHRwOi8vY3J0LnRlc3Q0LmJ1\n" +
                    "eXBhc3Mubm8vY3J0L0JQQ2xhc3MzVDRDQTMuY2VyMA0GCSqGSIb3DQEBCwUAA4IB\n" +
                    "AQCmMpAGaNplOgx3b4Qq6FLEcpnMOnPlSWBC7pQEDWx6OtNUHDm56fBoyVQYKR6L\n" +
                    "uGfalnnOKuB/sGSmO3eYlh7uDK9WA7bsNU/W8ZiwYwF6PBRui2rrqYk3kj4NLTNl\n" +
                    "yh/AOO1a2FDFHu369W0zcjj5ns7qs0K3peXtLX8pVxA8RmjwdGe69P/2r6s2A5CB\n" +
                    "j7oXZJD0Yo2dJFdsZzonT900sUi+MWzlhj3LxU5/684NWc2NI6ZPof/dyYpy3K/A\n" +
                    "FzpDLWGSmaDO66hPl7EfoJxEiX0DNBaQzNIyRFPh0ir0jM+32ZQ4goR8bAtyhKeT\n" +
                    "yA/4+Qx1WQXS3wURCC0lsbMh\n" +
                    "-----END CERTIFICATE-----";
}
