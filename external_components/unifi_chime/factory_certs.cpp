// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright 2026 Qoole (https://github.com/Qoole)

#include "factory_certs.h"

const char FACTORY_CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICFTCCAbsCFGYDkXb/7M3JV+VkPVFmHx0tzANxMAoGCCqGSM49BAMCMIGLMQsw\n"
    "CQYDVQQGEwJUVzEPMA0GA1UEBwwGVGFpcGVpMR8wHQYDVQQKDBZVYmlxdWl0aSBO\n"
    "ZXR3b3JrcyBJbmMuMQ8wDQYDVQQLDAZkZXZpbnQxGDAWBgNVBAMMD2NhbWVyYS51\n"
    "Ym50LmRldjEfMB0GCSqGSIb3DQEJARYQc3VwcG9ydEB1Ym50LmNvbTAgFw0yMTA1\n"
    "MjcwOTM1MDlaGA8yMTIxMDUwMzA5MzUwOVowgYsxCzAJBgNVBAYTAlTXMQ8wDQYD\n"
    "VQQHDAZUYWlwZWkxHzAdBgNVBAoMFlViaXF1aXRpIE5ldHdvcmtzIEluYy4xDzAN\n"
    "BgNVBAsMBmRldmludDEYMBYGA1UEAwwPY2FtZXJhLnVibnQuZGV2MR8wHQYJKoZI\n"
    "hvcNAQkBFhBzdXBwb3J0QHVibnQuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
    "QgAEG/lce/gEabI2/0XpIPat95YpMsGZwPZbHdRquAV4vjdHoVBS5pgpe9hcKdq0\n"
    "wmjyYNuqFdIR/pU5RKQoTPGf0DAKBggqhkjOPQQDAgNIADBFAiEA6yTyuhfbMNta\n"
    "yt017JHWE155L3GweFcolnFPe9YsGNcCIBsJhjE7QhwPsrHoSRzXZl850fT7mSoh\n"
    "1h0aaBLEp5wi\n"
    "-----END CERTIFICATE-----\n";

const size_t FACTORY_CA_PEM_LEN = sizeof(FACTORY_CA_PEM);

const char FACTORY_KEY_PEM[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIMNmCCg/60yJHRGyIKGJGwHgkPCE+haVcG4i0vh576aBoAoGCCqGSM49\n"
    "AwEHoUQDQgAEG/lce/gEabI2/0XpIPat95YpMsGZwPZbHdRquAV4vjdHoVBS5pgp\n"
    "e9hcKdq0wmjyYNuqFdIR/pU5RKQoTPGf0A==\n"
    "-----END EC PRIVATE KEY-----\n";

const size_t FACTORY_KEY_PEM_LEN = sizeof(FACTORY_KEY_PEM);
