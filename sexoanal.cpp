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


/* un poco de mierda para reservar el espacio en memoria del proceso remoto */
unsigned char puke[] = "C:/Users/Techie12/source/repos/sexoanal/x64/debug/DLL1.dll";

int main(int argc, char* argv[]) {


	PID = 21000;
	
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
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(puke), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	PVOID lpBuffer = malloc(sizeof(puke));
	memcpy(lpBuffer, &puke[0], sizeof(puke));
	int writed = WriteProcessMemory(hProcess, rBuffer, lpBuffer, sizeof(puke), NULL);
	int dllAddr = 
	printf("add %d %p,",writed, rBuffer);

	PVOID loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, rBuffer, 0, 0);

	return EXIT_SUCCESS;
	
}