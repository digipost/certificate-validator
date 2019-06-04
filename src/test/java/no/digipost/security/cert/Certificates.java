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
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

public final class Certificates {


    public static final String DIGIPOST_VIRKSOMHETSSERTIFIKAT_TEST =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIE9DCCA9ygAwIBAgILATeICpJlVUsWQIowDQYJKoZIhvcNAQELBQAwUTELMAkG\n" +
            "A1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MSMwIQYDVQQD\n" +
            "DBpCdXlwYXNzIENsYXNzIDMgVGVzdDQgQ0EgMzAeFw0xNzAzMjgwNzA0MzVaFw0y\n" +
            "MDAzMjgyMjU5MDBaMFoxCzAJBgNVBAYTAk5PMRgwFgYDVQQKDA9QT1NURU4gTk9S\n" +
            "R0UgQVMxHTAbBgNVBAMMFFBPU1RFTiBOT1JHRSBBUyBURVNUMRIwEAYDVQQFEwk5\n" +
            "ODQ2NjExODUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5xfhyZbBR\n" +
            "B0StkKdZOgbAWJxQdLAhPRZ6DiLNj2BfvXWuwi89f5Gu9N13wVNSkcxC3kVnxxXm\n" +
            "VJT+cvxyyOi6y2He+tstA1CS7LYPTKv0Xzk6SmWGWYederMj22L0C4jwDfVIlySB\n" +
            "/Y/PLCRDCMewjlwG152GYeslQP4mwC6LjacqgNVvcwJLYAUrMIKzbtrnS+oPb2ep\n" +
            "LU8O/frQWOoSEufEaSA/rh6jLWfblkoir8No5aDsIhTd9ILMIOIJwDHdo29mGXjp\n" +
            "mVQRBGRBLLDhDt0uXkYZIYDg3gRpCbr4vGmUvAy4VNiZLYFhsdkfUazDOzBAn+BI\n" +
            "Pssqj/Je5cfLAgMBAAGjggHCMIIBvjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFD+u\n" +
            "9XgLkqNwIDVfWvr3JKBSAfBBMB0GA1UdDgQWBBTlibBg2L61AZXa+GAJtElRDIpA\n" +
            "NjAOBgNVHQ8BAf8EBAMCBLAwFgYDVR0gBA8wDTALBglghEIBGgEAAwIwgbsGA1Ud\n" +
            "HwSBszCBsDA3oDWgM4YxaHR0cDovL2NybC50ZXN0NC5idXlwYXNzLm5vL2NybC9C\n" +
            "UENsYXNzM1Q0Q0EzLmNybDB1oHOgcYZvbGRhcDovL2xkYXAudGVzdDQuYnV5cGFz\n" +
            "cy5uby9kYz1CdXlwYXNzLGRjPU5PLENOPUJ1eXBhc3MlMjBDbGFzcyUyMDMlMjBU\n" +
            "ZXN0NCUyMENBJTIwMz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MIGKBggrBgEF\n" +
            "BQcBAQR+MHwwOwYIKwYBBQUHMAGGL2h0dHA6Ly9vY3NwLnRlc3Q0LmJ1eXBhc3Mu\n" +
            "bm8vb2NzcC9CUENsYXNzM1Q0Q0EzMD0GCCsGAQUFBzAChjFodHRwOi8vY3J0LnRl\n" +
            "c3Q0LmJ1eXBhc3Mubm8vY3J0L0JQQ2xhc3MzVDRDQTMuY2VyMA0GCSqGSIb3DQEB\n" +
            "CwUAA4IBAQBeGZyhAOQ0HsTuVIF9r+8E0whlig1N4AufFRGfIJdTu7lulMF6IZ79\n" +
            "hDqR4Fe+66/fjeBwCx3M9ulnjOglUcJLTmn9Fp1X/GwDs8HTP0h/uVByFnweSkbF\n" +
            "1oDqea+/lmOnULwMaCLG+ibzvd5igG9QRWoc3xQJE0XNajj2SdlKmN8+o3TxhOdL\n" +
            "fiDo5BoqF+XffwNtVR/QsLjaCiyM9rJXfetFRwH7aB/Slk9ygICXCdPP/kQz5T9d\n" +
            "E5Lzi0bVe2OpiYUD6ZC38W0MDkmvEJv0v5heFxOsvcSfjZP1j8asg4EASiiiWMoQ\n" +
            "6UI0kLtd8MJtTJRdQoxhXEiQdaz97AFj\n" +
            "-----END CERTIFICATE-----";

    public static final String DIGIPOST_VIRKSOMHETSSERTIFIKAT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIE1DCCA7ygAwIBAgILCvh7UWggEIpKBNkwDQYJKoZIhvcNAQELBQAwSzELMAkG\n" +
            "A1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MR0wGwYDVQQD\n" +
            "DBRCdXlwYXNzIENsYXNzIDMgQ0EgMzAeFw0xNzA0MTkxMjA3MjNaFw0yMDA0MTky\n" +
            "MTU5MDBaMGgxCzAJBgNVBAYTAk5PMRgwFgYDVQQKDA9QT1NURU4gTk9SR0UgQVMx\n" +
            "ETAPBgNVBAsMCERpZ2lwb3N0MRgwFgYDVQQDDA9QT1NURU4gTk9SR0UgQVMxEjAQ\n" +
            "BgNVBAUTCTk4NDY2MTE4NTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "ALmE/TIlGwjcnZesMF+8i80UxFhliJPMWNKIcAqocgxnCQUPY2mY3iadOwY0n8sk\n" +
            "rRPqWzVzYOBmXc0DsHQOj3wEnMjsrDgIt5j/VSfNys+GLlr7Q7UlQQVtz595fyOf\n" +
            "U2106DFSuP7cCriDjQrcvkH4ENkjG2iFiXnR8sYJDpdrTgu4SiH6EZgxCtqS3EGv\n" +
            "XtzYnC+UAXtf3S/HGIG+TFrwr+7syh4LGovH6dkL4eVgJEarO8pOAvOvbKDOd9vp\n" +
            "uzu0BJHSOATEPJDr4NpqSD4iZd+2dBEWGKmpqGIt05I9XMWG7VRkYLoyYr8elKna\n" +
            "+48rsaZaFn3qBDkN9fPQsx8CAwEAAaOCAZowggGWMAkGA1UdEwQCMAAwHwYDVR0j\n" +
            "BBgwFoAUzMP4B7ecbXpO9acrHQX5s0cckdEwHQYDVR0OBBYEFO+mV8Bjyp+5XmZV\n" +
            "Y7iwIflv+Jo2MA4GA1UdDwEB/wQEAwIEsDAVBgNVHSAEDjAMMAoGCGCEQgEaAQMC\n" +
            "MIGlBgNVHR8EgZ0wgZowL6AtoCuGKWh0dHA6Ly9jcmwuYnV5cGFzcy5uby9jcmwv\n" +
            "QlBDbGFzczNDQTMuY3JsMGegZaBjhmFsZGFwOi8vbGRhcC5idXlwYXNzLm5vL2Rj\n" +
            "PUJ1eXBhc3MsZGM9Tk8sQ049QnV5cGFzcyUyMENsYXNzJTIwMyUyMENBJTIwMz9j\n" +
            "ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MHoGCCsGAQUFBwEBBG4wbDAzBggrBgEF\n" +
            "BQcwAYYnaHR0cDovL29jc3AuYnV5cGFzcy5uby9vY3NwL0JQQ2xhc3MzQ0EzMDUG\n" +
            "CCsGAQUFBzAChilodHRwOi8vY3J0LmJ1eXBhc3Mubm8vY3J0L0JQQ2xhc3MzQ0Ez\n" +
            "LmNlcjANBgkqhkiG9w0BAQsFAAOCAQEAiVNjQze8SUYHmsiaMTgoJM4Xmneks48W\n" +
            "6facCpPrMNgRVvW9puWtMRnMasY/rXmpsz/psyktXybY4jiVAX3k+P52e8aMMSI+\n" +
            "DGh4U4aNX9PwKRIgPEQ8wFRsP2kk9vgyFhQ3lJBhxIrtv+jeA5z0naeoUy8lTNQ5\n" +
            "YliiZlygZifFaHAC51xobmBHDeuG1H305vjji0sQ9hO4NcOOq75hiKxUiPc07uYf\n" +
            "CDOxwDSpoz1XwUIaUpCY6FNvUnO1itzqundL0iODe5hsfTK6Ceq9ofqgwPolvXai\n" +
            "7PBcA5hb9tY3vF0xfh0p2or00dpLZ4G3Ga6pGo7AuJlWM+tFSGifbw==\n" +
            "-----END CERTIFICATE-----";

    public static final String DIGIPOST_SELFSIGNED_SERTIFIKAT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIF/zCCA+egAwIBAgICEBQwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCTk8x\n" +
            "DTALBgNVBAgMBE9zbG8xGDAWBgNVBAoMD1Bvc3RlbiBOb3JnZSBBUzERMA8GA1UE\n" +
            "CwwIRGlnaXBvc3QxHjAcBgNVBAMMFURpZ2lwb3N0IFRlc3QgUm9vdCBDQTAeFw0x\n" +
            "OTA2MDQwNzIzMTBaFw0zOTA1MzAwNzIzMTBaMIGIMQswCQYDVQQGEwJOTzENMAsG\n" +
            "A1UECAwET3NsbzEYMBYGA1UECgwPUG9zdGVuIE5vcmdlIEFTMREwDwYDVQQLDAhE\n" +
            "aWdpcG9zdDE9MDsGA1UEAww0ZGlnaXBvc3QtY2VydGlmaWNhdGUtdmFsaWRhdG9y\n" +
            "LXRlc3RzIFRlc3RpbnRlZ3Jhc2pvbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n" +
            "AgoCggIBAJUDhcocmXjYTdHCUZHNcgsxiQBK2vwqQUtNrs5/DE7kuGoJkqf+9syE\n" +
            "ISYuOqbp9psBZdQa/sqif3/0MGXBk9dUcWRjrAScF4B74ozcHfpSYiOxchsw0GIH\n" +
            "OIGZL8leX3wmrWHl2tUjRzwOFlTlgN9Hcz3qXDa9bc6iYhCVmMSRvg3tpIyj8CBc\n" +
            "aDVkPmUlwKadJVQYip5LYI0+OFgGRP/+Fq2a1wD8n0ODpHQHTUd2dxm9GsvTl9A5\n" +
            "JyJFTVQwPQZwOXfsudrsdwr9jaXc4/cS5baLsxPfLm3k4bHXOzoEBXY8mYMLYFSY\n" +
            "OasdD3f0E4mQlS2LHEp28hmAOOPiDmSYKDEfkM8pGxDKweVIwNlQHKpIvdwtszot\n" +
            "kdoO2aNATscSpactufai1loDVQVjZKXRe1ZxWW33iBUksamSX99QiDjPtBKSSKec\n" +
            "tz8n8QRDRpetQ8mVIm1P1knT7i+LIN5VX/oVOeKgBLQ1DYvqpIbjB1Xp4faubJTw\n" +
            "cMXQoAik1/JeJ6NE6sDByhno6IxgH/0mcxfnInm0Ug9alr/1hlLOmagV5tU3Ub/b\n" +
            "Yn9X8NM+5iKFuZnFKBP2ogwl7RshFIAtAHhITTfXYZA+OOenAqjz2TLJFYO/B62Q\n" +
            "jqYLwdbObK25jyUbnW6gm7PuI33Lv9u3KHhkTwtlBrGkS4RY4duVAgMBAAGjgZAw\n" +
            "gY0wCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBsAwHQYDVR0OBBYEFJH6SoCt\n" +
            "93HYoFzuXmXeDCMbR9mwMB8GA1UdIwQYMBaAFO1A0nFm1/guusvJyL8KP1xhId36\n" +
            "MA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw\n" +
            "DQYJKoZIhvcNAQELBQADggIBADEbScuLGXXBcRYCyHdG9TIM8yMPl32N6lQvCbO9\n" +
            "KymKdcps88kYlj7nHwO85LAakreP5XPBp53yG4qSdUFEae8pYXTuhAy8686jEYZD\n" +
            "CUk6UHBldChe1XVuUj2fdSMEIStjvxKHowE+mtqCdtVRsbEPTcSGq4V0uwHHPJnA\n" +
            "cERoSzuqfRMphjfWJInR5GMSmEUsdEzkfSZimV4LqRw6xWBandPBNR3k3vHxhGZi\n" +
            "hMit/jCwUYrbX2X0GYJjA9vLExzqi0SJw/ikFXBTo6cySrpK8+Hv/w1pbPXsqLvF\n" +
            "xDn+XEPSavW7qqUsbQ406pdmGt14DCC9n+uksfGtf8O1ljp5d5Q8AWO1yZlN+LRK\n" +
            "SEZOH7XSsKZe+C0uXhIqR3nLUiIkwyUh/G0NQRjJHRUMSE2IX3OnX3PyeM49ZMr9\n" +
            "BXADvWuBme+3iDvg4QY1u0E9KzC4quv9bhKRrA9qZgr0PDpUEBNU/DDeP9d3X+8s\n" +
            "I+fjCXmehxw/RnH0bSg6sscBz1qFIc/UxYaIPf6OIbNE98NIj3073TEwrIL72k5k\n" +
            "ysAb7c1/ftdsENGhORQ9Y8vh2pF9LZwFjD6Rks5JyE3J0fx7f9fqybaSofOH53SH\n" +
            "b3yoQ6NUHuA0JhTgm/9GBNGf811Nqgnau2e7/8QNz73FK6lTfGotfyl2cUqa0IJM\n" +
            "z7v7\n" +
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

    public static X509Certificate digipostVirksomhetsTestsertifikat() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(DIGIPOST_VIRKSOMHETSSERTIFIKAT_TEST.getBytes()));
    }

    private static final X509Certificate DIGIPOST_TEST_ROOT_CA_CERT; static {
        try (InputStream certStream = Certificates.class.getResourceAsStream("/sertifikater/test/digipost_test_root_ca.cert.pem")) {
            DIGIPOST_TEST_ROOT_CA_CERT = DigipostSecurity.readCertificate(certStream);
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public static X509Certificate digipostTestRotsertifikat() {
        return DIGIPOST_TEST_ROOT_CA_CERT;
    }

    public static X509Certificate digipostUtstedtTestsertifikat() {
        return DigipostSecurity.readCertificate(new ByteArrayInputStream(DIGIPOST_SELFSIGNED_SERTIFIKAT.getBytes()));
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
