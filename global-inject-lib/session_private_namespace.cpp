#include "stdafx.h"
#include "session_private_namespace.h"
#include "functions.h"

namespace
{
	constexpr auto boundaryDescriptorName = L"CustomizationBoundary";

	wil::unique_boundary_descriptor BuildBoundaryDescriptor()
	{
		wil::unique_boundary_descriptor boundaryDesc(CreateBoundaryDescriptor(boundaryDescriptorName, 0));
		THROW_LAST_ERROR_IF_NULL(boundaryDesc);

		{
			wil::unique_sid pSID;
			SID_IDENTIFIER_AUTHORITY SIDWorldAuth = SECURITY_WORLD_SID_AUTHORITY;
			THROW_IF_WIN32_BOOL_FALSE(
				AllocateAndInitializeSid(&SIDWorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSID));

			THROW_IF_WIN32_BOOL_FALSE(AddSIDToBoundaryDescriptor(boundaryDesc.addressof(), pSID.get()));
		}

		{
			wil::unique_sid pSID;
			SID_IDENTIFIER_AUTHORITY SIDMandatoryLabelAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
			THROW_IF_WIN32_BOOL_FALSE(
				AllocateAndInitializeSid(&SIDMandatoryLabelAuth, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pSID));

			THROW_IF_WIN32_BOOL_FALSE(AddIntegrityLabelToBoundaryDescriptor(boundaryDesc.addressof(), pSID.get()));
		}

		return boundaryDesc;
	}
}

namespace SessionPrivateNamespace
{
	int MakeName(WCHAR szPrivateNamespaceName[PrivateNamespaceMaxLen + 1], DWORD dwSessionManagerProcessId) noexcept
	{
		static_assert(PrivateNamespaceMaxLen + 1 == sizeof("CustomizationSession1234567890"));
		return swprintf_s(szPrivateNamespaceName, PrivateNamespaceMaxLen + 1, L"CustomizationSession%u", dwSessionManagerProcessId);
	}

	wil::unique_private_namespace_destroy Create(DWORD dwSessionManagerProcessId)
	{
		wil::unique_boundary_descriptor boundaryDesc(BuildBoundaryDescriptor());

		wil::unique_hlocal secDesc;
		THROW_IF_WIN32_BOOL_FALSE(GetFullAccessSecurityDescriptor(&secDesc, nullptr));

		SECURITY_ATTRIBUTES secAttr = { sizeof(SECURITY_ATTRIBUTES) };
		secAttr.lpSecurityDescriptor = secDesc.get();
		secAttr.bInheritHandle = FALSE;

		WCHAR szPrivateNamespaceName[PrivateNamespaceMaxLen + 1];
		MakeName(szPrivateNamespaceName, dwSessionManagerProcessId);

		wil::unique_private_namespace_destroy privateNamespace(
			CreatePrivateNamespace(&secAttr, (void*)boundaryDesc.get(), szPrivateNamespaceName));
		THROW_LAST_ERROR_IF_NULL(privateNamespace);

		return privateNamespace;
	}

	wil::unique_private_namespace_close Open(DWORD dwSessionManagerProcessId)
	{
		wil::unique_boundary_descriptor boundaryDesc(BuildBoundaryDescriptor());

		WCHAR szPrivateNamespaceName[PrivateNamespaceMaxLen + 1];
		MakeName(szPrivateNamespaceName, dwSessionManagerProcessId);

		wil::unique_private_namespace_close privateNamespace(OpenPrivateNamespace((void*)boundaryDesc.get(), szPrivateNamespaceName));
		THROW_LAST_ERROR_IF_NULL(privateNamespace);

		return privateNamespace;
	}
}
