#pragma once

BOOL GetFullAccessSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_opt_ PULONG SecurityDescriptorSize);
