#include "stdafx.h"
#include "functions.h"
#include "engine_control.h"

int main()
{
	printf("Setting debug privilege... ");
	if (SetDebugPrivilege(TRUE)) {
		printf("OK\n");
	}
	else {
		printf("Failed, probably not running as admin\n");
	}

	try {
		printf("Loading engine... ");
		auto engineControl = EngineControl();
		printf("Done\n");

		while (true) {
			Sleep(1000);
			int count = engineControl.HandleNewProcesses();
			if (count == 1) {
				printf("Injected into a new process\n");
			}
			else if (count > 1) {
				printf("Injected into %d new processes\n", count);
			}
		}
	}
	catch (const std::exception& e) {
		printf("%s\n", e.what());
	}

	return 0;
}
