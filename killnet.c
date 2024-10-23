#include "killnet.h"

WCHAR* getProcessPath(DWORD pid)
{
    static WCHAR filename[MAX_PATH] = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL) {
        DWORD error = GetLastError();
        wprintf(L"[!] Error getting process handle. Error code: %lu\n", error);
        return NULL;
    }

    if (GetModuleFileNameExW(hProcess, NULL, filename, MAX_PATH)) {
        wprintf(L"Process ID: %u\n", pid);
        wprintf(L"Executable path: %s\n", filename);
    }
    else {
        DWORD error = GetLastError();
        wprintf(L"[!] Error getting executable path. Error code: %lu\n", error);
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);
    return filename;
}

void applyFilter(WCHAR* filename, FWPM_FILTER filter, DWORD result, HANDLE hEngine)
{
    FWP_BYTE_BLOB* appId = NULL;
    result = FwpmGetAppIdFromFileName(filename, &appId);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error retrieving App ID from filename. Error code: %d\n", result);
        free(filename);
        FwpmEngineClose(hEngine);
        return;
    }

    FWPM_FILTER_CONDITION condition;
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;

    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;

    // Add the filter for IPv4
    result = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error adding IPv4 filter. Error code: %d\n", result);
        free(filename);
        FwpmEngineClose(hEngine);
        return;
    }

    // Add the filter for IPv6
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.filterKey = connectv6;
    result = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error adding IPv4 filter. Error code: %d\n", result);
        free(filename);
        FwpmEngineClose(hEngine);
        return;
    }

    // Add the filter for IPv4
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    filter.filterKey = recv4;
    result = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error adding IPv4 filter. Error code: %d\n", result);
        free(filename);
        FwpmEngineClose(hEngine);
        return;
    }

    // Add the filter for IPv6
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    filter.filterKey = recv6;
    result = FwpmFilterAdd(hEngine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error adding IPv4 filter. Error code: %d\n", result);
        free(filename);
        FwpmEngineClose(hEngine);
        return;
    }

    printf("[*] Filter added successfully\n");

    // Cleanup
    free(filename);
}

int deleteFilter(DWORD result, HANDLE hEngine)
{
    result = FwpmFilterDeleteByKey(hEngine, &connectv4);
    if (result != ERROR_SUCCESS)
    {
        printf("Error deleting filters\n");
        return -1;
    }

    result = FwpmFilterDeleteByKey(hEngine, &connectv6);
    if (result != ERROR_SUCCESS)
    {
        printf("Error deleting filters\n");
        return -1;
    }

    result = FwpmFilterDeleteByKey(hEngine, &recv4);
    if (result != ERROR_SUCCESS)
    {
        printf("Error deleting filters\n");
        return -1;
    }

    result = FwpmFilterDeleteByKey(hEngine, &recv6);
    if (result != ERROR_SUCCESS)
    {
        printf("Error deleting filters\n");
        return -1;
    }

    return 0;
}

void prepareFilter(char* argument, int type)
{
    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error opening WFP engine. Error code: %d\n", result);
        return;
    }

    WCHAR filterName[] = L"Killnet block";
    FWPM_FILTER filter = { 0 };
    filter.displayData.name = filterName;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.filterKey = connectv4;
    filter.action.type = FWP_ACTION_BLOCK;

    // PID
    if (type == PID_TYPE) {
        DWORD pid = stringToDWORD(argument);
        WCHAR* filename = getProcessPath(pid);

        applyFilter(filename, filter, result, hEngine);
    }

    // Filepath
    else if (type == FILENAME_TYPE) {
        // Get appId from argv[2]
        int wcharSize = MultiByteToWideChar(CP_ACP, 0, argument, -1, NULL, 0);
        if (wcharSize == 0) {
            printf("[!] Error converting filename to WCHAR\n");
            FwpmEngineClose(hEngine);
            return;
        }

        WCHAR* filename = (WCHAR*)malloc(wcharSize * sizeof(WCHAR));
        if (filename == NULL) {
            printf("[!] Error allocating memory for filename\n");
            FwpmEngineClose(hEngine);
            return;
        }

        MultiByteToWideChar(CP_ACP, 0, argument, -1, filename, wcharSize);

        applyFilter(filename, filter, result, hEngine);
    }
    else if (type == DELETE_TYPE)
    {
        deleteFilter(result, hEngine);
        printf("[+] Filters deleted!\n");
    }
    else
    {
        printf("[!] Unrecognized type\n");
    }

    FwpmEngineClose(hEngine);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("[!] Usage examples:\n* killnet.exe -p <PID>\n* killnet.exe -f <Filename path>\n* killnet.exe -delete");
		return -1;
	}

	if (strcmp(argv[1], "-p") == 0) 
	{
		printf("[*] Applying block to PID %s\n", argv[2]);
		prepareFilter(argv[2], PID_TYPE);
	}
	else if (strcmp(argv[1], "-f") == 0) 
	{
		printf("[*] Applying block to file %s\n", argv[2]);
		prepareFilter(argv[2], FILENAME_TYPE);
	}
    else if (strcmp(argv[1], "-delete") == 0)
    {
        printf("[*] Deleting filters...\n");
        prepareFilter(argv[2], DELETE_TYPE);
    }
	else
	{
		printf("[!] Invalid argument. Use -p or -f.\n");
		return -1;
	}

	return 0;
}
