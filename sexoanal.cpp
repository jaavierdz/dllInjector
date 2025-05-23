/* DLL Injector v1 */
/* Written by Javierdz */

#include <windows.h>
#include <stdio.h>
/* Esto son las variables para debug (verbose) */
const char* ok = "[+]";
const char* inf = "[*]";
const char* err = "[-]";


/* Handles y variable del PID */
DWORD PID = NULL;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL;


/* ruta de la dll */
unsigned char dll[] = "C:/Users/Techie12/source/repos/sexoanal/x64/debug/DLL1.dll";

int main(int argc, char* argv[]) {
	/* Comprobamos si por casualidad el usuario no ha especificado ningun PID */
	if (argc < 2 ) {
		printf("%s No process ID specified for injection\n", err);
		return EXIT_FAILURE;
	}


	PID = atoi(argv[1]);
	
	printf("%s intentando abrir un handle al proceso (%ld)\n", inf, PID);

	/* Aqui abrimos el handle al proceso especificado a la hora de ejecucion */
	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		PID
	);
	if (hProcess == NULL) {
		printf("%s no se pudo abrir un handle al proceso (%ld), error %ld", err, PID, GetLastError());
		return EXIT_FAILURE;
	}

	/* Alocación y asignacion de bytes a la memoria del proceso */
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dll), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	PVOID lpBuffer = malloc(sizeof(dll));
	memcpy(lpBuffer, &dll[0], sizeof(dll));
	int wrote = WriteProcessMemory(hProcess, rBuffer, lpBuffer, sizeof(dll), NULL);
	printf("add %d %p\n",wrote, rBuffer);
    if (wrote == 0) {
		printf("%s no se pudo escribir en la memoria del proceso (%ld), error %ld", err, PID, GetLastError());
		return EXIT_FAILURE;
	}
	/* Aqui es donde se inyecta la DLL*/
	printf("%s Trying to inyect DLL into desired process (%ld)\n", inf, PID);
	PVOID loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, rBuffer, 0, 0);
	if (CreateRemoteThread == NULL) {
		printf("%s Could not inject DLL to the PID (%ld), error %ld", err, PID, GetLastError());
		printf("%s Variable written value = %ld", inf, wrote);
		printf("%s Variable rBuffer address = %p", inf, rBuffer);
		printf("%s Variable lpBuffer address = %p", inf, lpBuffer);
		printf("%s Variable PID = %ld", inf, PID);
		printf("%s Variable hProcess = %p", inf, hProcess);
		printf("%s Variable hThread = %p", inf, hThread);
		printf("%s Variable loadLibraryAddr = %p", inf, loadLibraryAddr);
		
		
		return EXIT_FAILURE;
	}
	else {
		printf("%s DLL (WROTEMEM) injected into the PID (%ld)\n", ok, PID);


	}
	return EXIT_SUCCESS;
}