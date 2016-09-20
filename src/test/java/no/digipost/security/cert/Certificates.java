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

import no.digipost.security.DigipostSecurity;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

public final class Certificates {


    public static final String DIGIPOST_TESTSERTIFIKAT =
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

    public static final String DIGIPOST_VIRKSOMHETSSERTIFIKAT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIE1DCCA7ygAwIBAgILA+jTV+nCPcYeg9wwDQYJKoZIhvcNAQELBQAwSzELMAkG\n" +
            "A1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MR0wGwYDVQQD\n" +
            "DBRCdXlwYXNzIENsYXNzIDMgQ0EgMzAeFw0xNDA2MjQxMjU0NDlaFw0xNzA2MjQy\n" +
            "MTU5MDBaMGgxCzAJBgNVBAYTAk5PMRgwFgYDVQQKDA9QT1NURU4gTk9SR0UgQVMx\n" +
            "ETAPBgNVBAsMCERpZ2lwb3N0MRgwFgYDVQQDDA9QT1NURU4gTk9SR0UgQVMxEjAQ\n" +
            "BgNVBAUTCTk4NDY2MTE4NTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AK1twtu2WT2T5GPYtwm8kbdCKkTu1qIIm7T+11RWk9NjQG+IqWZhJYUj+Myx/uoZ\n" +
            "oYxcjgoeLDilQq5pFJA9Oq0I26ZLuv8fi25660GlNfB07J0j9lbJs8uFxV/4+MUf\n" +
            "6zZ+h9JthTpa5HGkQSImm+UJ+AMLaaxXY8+P7RcPeVPPQIN2A212dSTVruMWbOP4\n" +
            "DF5683kIXfizuyI8bAC2Ytp3Mxy6bQdEBNc8gNSUmTRBTrqxmkfenM1fGknrMUvV\n" +
            "tYmT/OGm+6tWvIspIsGYOqFVTaMQUPlOEF6eqkXEnCRIbEZNNtVb7L9o60R2SNKf\n" +
            "X6OnJRTJjFmJ4DzCP4GfBCsCAwEAAaOCAZowggGWMAkGA1UdEwQCMAAwHwYDVR0j\n" +
            "BBgwFoAUzMP4B7ecbXpO9acrHQX5s0cckdEwHQYDVR0OBBYEFC4S7wHxmoiYgbix\n" +
            "YfsK3uBZIEXqMA4GA1UdDwEB/wQEAwIEsDAVBgNVHSAEDjAMMAoGCGCEQgEaAQMC\n" +
            "MIGlBgNVHR8EgZ0wgZowL6AtoCuGKWh0dHA6Ly9jcmwuYnV5cGFzcy5uby9jcmwv\n" +
            "QlBDbGFzczNDQTMuY3JsMGegZaBjhmFsZGFwOi8vbGRhcC5idXlwYXNzLm5vL2Rj\n" +
            "PUJ1eXBhc3MsZGM9Tk8sQ049QnV5cGFzcyUyMENsYXNzJTIwMyUyMENBJTIwMz9j\n" +
            "ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MHoGCCsGAQUFBwEBBG4wbDAzBggrBgEF\n" +
            "BQcwAYYnaHR0cDovL29jc3AuYnV5cGFzcy5uby9vY3NwL0JQQ2xhc3MzQ0EzMDUG\n" +
            "CCsGAQUFBzAChilodHRwOi8vY3J0LmJ1eXBhc3Mubm8vY3J0L0JQQ2xhc3MzQ0Ez\n" +
            "LmNlcjANBgkqhkiG9w0BAQsFAAOCAQEAYxPhuUmFnazKTqlpBtCIxcEt0wWHLEpv\n" +
            "5LRUGzcTts+O/JuUSrg3Hbwj1pNjXktZVwiGl1xn54Aq+q/NXopnESkcTNCWSyOw\n" +
            "fQ3nNOpeTypw5qPXg+D16GxAFeFCf+ln3VMgveTT+nAp37aFUqtLCc6VEnGnTB9V\n" +
            "d+4xpWxQ15Pb2SsougTwX8q9E7cAn0S/nnKDECLbwn+pNfjNys1T90sGZqjaDT4O\n" +
            "2DzIBVI5ubwMsG8+LCI4NhYcoiiKvgjNu9IMKGIYIoktyXNMKSGo5ZnPCE27Q54U\n" +
            "8MoXZAJn4jWMa0kV92iO0yNaOFJ732QKimgVJ7wsrBYv9K8+ZEhxmg==\n" +
            "-----END CERTIFICATE-----";


    public static final String DIFI = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFOjCCBCKgAwIBAgIKGQqI22LuZ+0U6TANBgkqhkiG9w0BAQsFADBRMQswCQYD\n" +
            "VQQGEwJOTzEdMBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxIzAhBgNVBAMM\n" +
            "GkJ1eXBhc3MgQ2xhc3MgMyBUZXN0NCBDQSAzMB4XDTE0MDYxNjA4NTYyNloXDTE3\n" +
            "MDYxNjIxNTkwMFowgaAxCzAJBgNVBAYTAk5PMSwwKgYDVQQKDCNESVJFS1RPUkFU\n" +
            "RVQgRk9SIEZPUlZBTFROSU5HIE9HIElLVDEhMB8GA1UECwwYU0RQIC0gbWVsZGlu\n" +
            "Z3N1dHZla3NsaW5nMSwwKgYDVQQDDCNESVJFS1RPUkFURVQgRk9SIEZPUlZBTFRO\n" +
            "SU5HIE9HIElLVDESMBAGA1UEBRMJOTkxODI1ODI3MIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAx6IPA2KSAkSupen5fFM1LEnW6CRqSK20wjpBnXf414W0\n" +
            "3eWUvBlw97c6k5sl2tYdn4aVb6Z9GeDaz1bLKN3XwhFGPk9PnjSIhrFJNAPnWVEB\n" +
            "DqGqfeMrEsYdOEgM2veBZDYkhVwipjr8AesmptTRAat61q+6hCJe8UZqjXb4Mg6Y\n" +
            "KSTAHfJdthAG06weBMgVouQkTkeIIawM+QPcKQ3Wao0gIZi17V0+8xzgDu1PXr90\n" +
            "eJ/Xjsw9t0C8Ey/3N7n3j3hplsZkjOJMBNHzbeBG/doroC6uzVURiuEn9Bc9Nk22\n" +
            "4b+7lOBZ1FvNNrJVUu5Ty3xyMDseCV7z1QTwW7wcpwIDAQABo4IBwjCCAb4wCQYD\n" +
            "VR0TBAIwADAfBgNVHSMEGDAWgBQ/rvV4C5KjcCA1X1r69ySgUgHwQTAdBgNVHQ4E\n" +
            "FgQU6JguiqDjkgjEGRHhzkbeKeqyWQEwDgYDVR0PAQH/BAQDAgSwMBYGA1UdIAQP\n" +
            "MA0wCwYJYIRCARoBAAMCMIG7BgNVHR8EgbMwgbAwN6A1oDOGMWh0dHA6Ly9jcmwu\n" +
            "dGVzdDQuYnV5cGFzcy5uby9jcmwvQlBDbGFzczNUNENBMy5jcmwwdaBzoHGGb2xk\n" +
            "YXA6Ly9sZGFwLnRlc3Q0LmJ1eXBhc3Mubm8vZGM9QnV5cGFzcyxkYz1OTyxDTj1C\n" +
            "dXlwYXNzJTIwQ2xhc3MlMjAzJTIwVGVzdDQlMjBDQSUyMDM/Y2VydGlmaWNhdGVS\n" +
            "ZXZvY2F0aW9uTGlzdDCBigYIKwYBBQUHAQEEfjB8MDsGCCsGAQUFBzABhi9odHRw\n" +
            "Oi8vb2NzcC50ZXN0NC5idXlwYXNzLm5vL29jc3AvQlBDbGFzczNUNENBMzA9Bggr\n" +
            "BgEFBQcwAoYxaHR0cDovL2NydC50ZXN0NC5idXlwYXNzLm5vL2NydC9CUENsYXNz\n" +
            "M1Q0Q0EzLmNlcjANBgkqhkiG9w0BAQsFAAOCAQEAKOTM1zSdGHWUBKPzDPYCcci9\n" +
            "cpbktd2WuBg028bRC0NwKSWUKeuUfWesTiu/P4UlYGe86qd/+z3MNpN89aGA8pr0\n" +
            "E0WpI+NM+v+Cb0dQwxHASHtrkVo9CVx6V6/QSBqIUEMfNquDHzxB2/mXbv6GuO5e\n" +
            "Il3OSVKg7Ffd/1wdE6zeMmHQO+zRpfj+OVEhNPb5cLa13Ah9+JrMkr1O7VUFbozL\n" +
            "QgFPhuI8/5+u8U/6cDOOmcFV4f4IYUmhbcLiW5MQnvaJ8044+uInOQTNtSkKmZAo\n" +
            "7Jnm4KUyhFXftJOStOHSlODOQcepVS7csszO5yWQRMTV8doEsaH5p/LBXYF56Q==\n" +
            "-----END CERTIFICATE-----";

    public static final String EBOKS = "-----BEGIN CERTIFICATE-----\n" +
            "MIIE+DCCA+CgAwIBAgIKGQiM/jonpcG0VTANBgkqhkiG9w0BAQsFADBRMQswCQYD\n" +
            "VQQGEwJOTzEdMBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxIzAhBgNVBAMM\n" +
            "GkJ1eXBhc3MgQ2xhc3MgMyBUZXN0NCBDQSAzMB4XDTE0MDYxMjEzNTYzOFoXDTE3\n" +
            "MDYxMjIxNTkwMFowXzELMAkGA1UEBhMCTk8xEjAQBgNVBAoMCUUtQk9LUyBBUzEU\n" +
            "MBIGA1UECwwLT3BlcmF0aW9uIDExEjAQBgNVBAMMCUUtQk9LUyBBUzESMBAGA1UE\n" +
            "BRMJOTk2NDYwMzIwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDwI\n" +
            "/8AEOlml4abZt+zXRTxQuzuWTVx8QS2a2zE0BdUE+PO3K8QQpfPzIZVHSrhiDr03\n" +
            "VRW2zJ5qz2peGhwNw1BRBltndJLuSJBqSdfJ2TbayoBQoHJkg7YvPi11LsM2aYE7\n" +
            "5tiKN/FUqKIgqMiOz0rbTyjOcNI1cD6ZC0xskZN1ONJqG5Jxqc3NOpPTco/YA7s4\n" +
            "1v1gUPdPfoXlu5tgnmiMh4Ixwr7x7FK80aj3Akg0eWmHI8P1IxJU8hJI6sthYO0Z\n" +
            "2d8RCLeXIc4pXAkRBvgKC8I8HEYk6pDxR3UvFlwC96Mj4Ne0EN8yo3ODtT1chPp7\n" +
            "iyUPiDvNhqSRrp8GEQIDAQABo4IBwjCCAb4wCQYDVR0TBAIwADAfBgNVHSMEGDAW\n" +
            "gBQ/rvV4C5KjcCA1X1r69ySgUgHwQTAdBgNVHQ4EFgQUBL6S6KHLV/uxUDs5bB6n\n" +
            "3jZUP/4wDgYDVR0PAQH/BAQDAgSwMBYGA1UdIAQPMA0wCwYJYIRCARoBAAMCMIG7\n" +
            "BgNVHR8EgbMwgbAwN6A1oDOGMWh0dHA6Ly9jcmwudGVzdDQuYnV5cGFzcy5uby9j\n" +
            "cmwvQlBDbGFzczNUNENBMy5jcmwwdaBzoHGGb2xkYXA6Ly9sZGFwLnRlc3Q0LmJ1\n" +
            "eXBhc3Mubm8vZGM9QnV5cGFzcyxkYz1OTyxDTj1CdXlwYXNzJTIwQ2xhc3MlMjAz\n" +
            "JTIwVGVzdDQlMjBDQSUyMDM/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDCBigYI\n" +
            "KwYBBQUHAQEEfjB8MDsGCCsGAQUFBzABhi9odHRwOi8vb2NzcC50ZXN0NC5idXlw\n" +
            "YXNzLm5vL29jc3AvQlBDbGFzczNUNENBMzA9BggrBgEFBQcwAoYxaHR0cDovL2Ny\n" +
            "dC50ZXN0NC5idXlwYXNzLm5vL2NydC9CUENsYXNzM1Q0Q0EzLmNlcjANBgkqhkiG\n" +
            "9w0BAQsFAAOCAQEARj4WegvcMeqvt8R2BxB/uoNIjATmoUxlUc1f/vLkqq0fNGMt\n" +
            "RDAJWlQJ26P6Q+05G+85mK0DkRNWEjZNnX/NzMijygYwgHc0KukMoIVfYngc02Vn\n" +
            "p2QNk5YC+EGF3WjtuD9D653WkA/eKXNGEkyKPO4Okgr5akDWqUORH2ZvgyIg+r/f\n" +
            "AScTxj8YhAdooXBh5TSQqWyyCLxspY7TY/qiQ5Yk1nQTUIkrBh3UD2VSeR+ymozO\n" +
            "9DxzboFRh87BgoT0c9scVo7yWpEkMcjUdZnpvqDQ0vtKFHz/VR7JfRFWpx7JG4Cs\n" +
            "xDCnMjfCd/jSllWUjrUmKVj7es8CqXcQnjTUZg==\n" +
            "-----END CERTIFICATE-----";


    public static final String EBOKS_COMMFIDES = "-----BEGIN CERTIFICATE-----\n" +
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
            "-----END CERTIFICATE-----";




    /**
     * Revoked certificate, acquired from <tt>revoked.grc.com</tt> using
     * <blockquote>
     * <tt>openssl s_client -host revoked.grc.com -port 443 -prexit -showcerts</tt>
     * </blockquote>
     */
    public static final String REVOKED =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIE7jCCA9agAwIBAgISESFVaI04B3XaNMXfl0M+0/anMA0GCSqGSIb3DQEBBQUA\n" +
            "MFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYD\n" +
            "VQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTQw\n" +
            "NDIzMTUzNzUyWhcNMTcwNDIzMTUzNzUyWjBKMQswCQYDVQQGEwJVUzEhMB8GA1UE\n" +
            "CxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRgwFgYDVQQDEw9yZXZva2VkLmdy\n" +
            "Yy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDemi+5M5XRD7PR\n" +
            "/4177a6x7upbXMm2b79x/PwBELElAsUq+qtmoBs0FXiMmOfxp1BUW3KO4fJGjMuE\n" +
            "G0UxJNo4YOYuNTW4PQnWpLqsGh8epcLi7DDQax+yKU4VaTOnHqJDjyQjiVvqojkJ\n" +
            "nzaSMSrUgbr7gfQwrmUVlSYhMb1j4HMQUPEyvRtkeevwBU5PHsUEIZBheTo0P8RC\n" +
            "1BvxXl6cSAdKiOgiloDGEAKwAa1u8ZJWtuPQbp2fbOIyMygwjo8F1JC7ybw4lT6c\n" +
            "UluSPZew2LPLRIJea8nYjGl1jEbCm3I8gnWAcOywjgSCv3egvxDA1NrgGjKBszXd\n" +
            "pZdnZLmDAgMBAAGjggG/MIIBuzAOBgNVHQ8BAf8EBAMCBaAwSQYDVR0gBEIwQDA+\n" +
            "BgZngQwBAgEwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\n" +
            "b20vcmVwb3NpdG9yeS8wKAYDVR0RBCEwH4IPcmV2b2tlZC5ncmMuY29tggxtYWls\n" +
            "LmdyYy5jb20wCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\n" +
            "AwIwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9n\n" +
            "cy9nc2RvbWFpbnZhbGcyLmNybDCBiAYIKwYBBQUHAQEEfDB6MEEGCCsGAQUFBzAC\n" +
            "hjVodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2RvbWFpbnZh\n" +
            "bGcyLmNydDA1BggrBgEFBQcwAYYpaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29t\n" +
            "L2dzZG9tYWludmFsZzIwHQYDVR0OBBYEFHI8mO4OWDHnVO+3VJ6CsEaSE1JfMB8G\n" +
            "A1UdIwQYMBaAFJat+rBbuYNkKnbCHIpp2kLc/v0oMA0GCSqGSIb3DQEBBQUAA4IB\n" +
            "AQCSJwP5JwWeGblum7enlfmALaBZ+HpA7GwaCopvR2+oEI/saMalUYTog8B+m9Xr\n" +
            "zF4iCkAnxoe3PYlfSAONioXQA9qVrsJsrQhdfgWuFsQOwu30bwhpolxk0M50wYPE\n" +
            "FxAIfwW/FsCkUFQ/5t0yUuiGCAIhGQ6mU39RkC6t43NyzVAWy1cDL30VSRRtppjl\n" +
            "WnHI9r3t8wPyu0nVOWq1IQ+BWnrO9F7Eb8dvgbSRa+ZL+p6eDX+6OEp8IxVToTa7\n" +
            "4LN/oqAYvkOh5k8sBrwqUZWUV0emBPI0vcT2LoBQDjziBk/PcssQj8XK2VLJ8smp\n" +
            "iitPBGOk/ZlPIIN9//bfyVn+\n" +
            "-----END CERTIFICATE-----";


    /**
     * The issuer of the {@link #REVOKED} certificate.
     */
    public static final String REVOKED_ISSUER =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEWjCCA0KgAwIBAgILBAAAAAABL07hQUMwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n" +
            "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n" +
            "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0MTMxMDAw\n" +
            "MDBaFw0yMjA0MTMxMDAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n" +
            "YWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0\n" +
            "aW9uIENBIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxo83A\n" +
            "3zNAJuveWteUZtQBY8wzRIng4rjCRw2PrWmGHKhzQgvxcvstrLURcoMi9lbnLsVn\n" +
            "cZ0AHDK84+0uCEWp5vrdyIyDBcFvS9AmSgv2G0XATX6TvA0nhO0wo+nGJibdLR/Y\n" +
            "i8POGdBb/Aif5NjiNeSgaKb2DaN0YEKyl4IkjkGk8i5eto6nbtlsfw07JDVq0Ktb\n" +
            "aveXAgA/UaanbnPKdw12fJu2MBoanPcfKHsOi0cf538FjMbJyLvP6dx6QS6hhtrU\n" +
            "ObLiE0CmqDr6D1MeT+xumAkbypp3s1WFhekuFrWdXlTxSnpsObpuFwY0s7JC4ffz\n" +
            "nJoLEUTeaniOsRNPAgMBAAGjggElMIIBITAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0T\n" +
            "AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUlq36sFu5g2QqdsIcimnaQtz+/SgwRwYD\n" +
            "VR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh\n" +
            "bHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9j\n" +
            "cmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwPQYIKwYBBQUHAQEEMTAvMC0GCCsG\n" +
            "AQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290cjEwHwYDVR0j\n" +
            "BBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEBADrn\n" +
            "/K6vBUOAJ3VBX6jwKI8fj4N+sri6rnUxJ4il5blOBEPSregTAKPbGQEwnmw8Un9c\n" +
            "3qtnw4QEVFGZnmMvvdW3wNXaAw5J0+Gzkk/fkk59riJqzti8/Hyua7aK6kVikBHT\n" +
            "C3GnXgYi/0046rk6bs1nGgJ/S/O/DnlvvtUpMllZHZYIm3CP9x5cRntO0J20U8gS\n" +
            "AhsNuzLrWVO5PhtWjRXI8UI/d/4f5W2eZh+r2rKDV7QMItKGvNoy18DtcIV8k6rw\n" +
            "l9w5EdLYieuNkKO2UCXLbNmmw2/7iFS45JJwh855O/DeNr8DBAA9+e+eqWek9IY+\n" +
            "I5e4KnHi7f5piGe/Jlw=\n" +
            "-----END CERTIFICATE-----";



    public static X509Certificate digipostVirksomhetssertifikat() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(DIGIPOST_VIRKSOMHETSSERTIFIKAT.getBytes()));
    }

    public static X509Certificate digipostTestsertifikat() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(DIGIPOST_TESTSERTIFIKAT.getBytes()));
    }


    /**
     * Revoked certificate, acquired using from revoked.grc.com
     * openssl s_client -host revoked.grc.com -port 443 -prexit -showcerts
     *
     * @see #REVOKED
     */
    public static X509Certificate revoked() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(REVOKED.getBytes()));
    }


    /**
     * The issuer of the {@link #revoked()} certificate.
     *
     * @see #REVOKED_ISSUER
     */
    public static X509Certificate revokedIssuer() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(REVOKED_ISSUER.getBytes()));
    }

}