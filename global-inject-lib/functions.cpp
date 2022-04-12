#include "stdafx.h"
#include "functions.h"

BOOL GetFullAccessSecurityDescriptor(
	_Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
	_Out_opt_ PULONG SecurityDescriptorSize)
{
	// http://rsdn.org/forum/winapi/7510772.flat
	//
	// For full access maniacs :)
	// Full access for the "Everyone" group and for the "All [Restricted] App Packages" groups.
	// The integrity label is Untrusted (lowest level).
	//
	// D - DACL
	// P - Protected
	// A - Access Allowed
	// GA - GENERIC_ALL
	// WD - 'All' Group (World)
	// S-1-15-2-1 - All Application Packages
	// S-1-15-2-2 - All Restricted Application Packages
	//
	// S - SACL
	// ML - Mandatory Label
	// NW - No Write-Up policy
	// S-1-16-0 - Untrusted Mandatory Level
	PCWSTR pszStringSecurityDescriptor = L"D:P(A;;GA;;;WD)(A;;GA;;;S-1-15-2-1)(A;;GA;;;S-1-15-2-2)S:(ML;;NW;;;S-1-16-0)";

	return ConvertStringSecurityDescriptorToSecurityDescriptor(
		pszStringSecurityDescriptor, SDDL_REVISION_1, SecurityDescriptor, SecurityDescriptorSize);
}
