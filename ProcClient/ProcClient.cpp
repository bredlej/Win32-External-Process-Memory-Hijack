// ProcClient.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
//
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>
#include <iterator>

int GetProcessId(char* ProcName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = NULL;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::string queryName(ProcName);
    std::wstring wQueryName(queryName.begin(), queryName.end());
    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::wstring pName(pe32.szExeFile);
            
            if (wQueryName.compare(pName) == 0)
                break;
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);

    return pe32.th32ProcessID;
}

template <class outIter>
std::vector<unsigned char*> get_addresses_of_memory_pattern_search(HANDLE process, std::string const& pattern, outIter output) {

    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info;
    std::vector<unsigned char*> addresses;
    for (p = NULL;
        VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info);
        p += info.RegionSize)
    {
        std::vector<char> buffer;
        std::vector<char>::iterator pos;

        if (info.State == MEM_COMMIT &&
            (info.Type == MEM_MAPPED || info.Type == MEM_PRIVATE))
        {
            SIZE_T bytes_read;
            buffer.resize(info.RegionSize);
            ReadProcessMemory(process, p, &buffer[0], info.RegionSize, &bytes_read);
            buffer.resize(bytes_read);
            for (pos = buffer.begin();
                buffer.end() != (pos = std::search(pos, buffer.end(), pattern.begin(), pattern.end()));
                ++pos)
            {
                auto address = p + (pos - buffer.begin());
                *output++ = p + (pos - buffer.begin());
                addresses.push_back(address);
            }
        }
    }
    return addresses;
}

class Process {
public:
    explicit Process() = delete;
    explicit Process(std::string process_name) : _id{ GetProcessId((char*)process_name.c_str()) }, _handle{ ::OpenProcess(PROCESS_ALL_ACCESS, false, _id), &::CloseHandle } {};
    explicit Process(int processId) : _id{processId}, _handle { ::OpenProcess(PROCESS_ALL_ACCESS, false, processId), & ::CloseHandle } {};
    HANDLE get() const { return _handle.get(); };
    int id() const { return _id; }
private:
    int _id;
    std::unique_ptr<std::remove_pointer<HANDLE>::type, BOOL(WINAPI*)(HANDLE)> _handle;
};

class HostModule {
public:
    explicit HostModule(const Process& process) {
        DWORD cbNeeded;

        if (EnumProcessModules(process.get(), &host_module, sizeof(host_module),
            &cbNeeded))
        {
            GetModuleBaseName(process.get(), host_module, process_name,
                sizeof(process_name) / sizeof(TCHAR));
        }
    }
    HMODULE address() const { return host_module; }
    const TCHAR* name() const { return process_name; };
private:
    HMODULE host_module;
    TCHAR process_name[MAX_PATH] = TEXT("<unknown>");
};

class MemoryInfo {
public:
    explicit MemoryInfo(const Process &process) {
        GetProcessMemoryInfo(process.get(), &_pmc, sizeof(_pmc));
    }
    void print() {
        printf("\tPageFaultCount: 0x%08X (%d)\n", _pmc.PageFaultCount, _pmc.PageFaultCount / 1024);
        printf("\tPeakWorkingSetSize: 0x%08X (%d)\n",
            _pmc.PeakWorkingSetSize, _pmc.PeakWorkingSetSize / 1024);
        printf("\tWorkingSetSize: 0x%08X (%d)\n", _pmc.WorkingSetSize, _pmc.WorkingSetSize / 1024);
        printf("\tQuotaPeakPagedPoolUsage: 0x%08X (%d)\n",
            _pmc.QuotaPeakPagedPoolUsage, _pmc.QuotaPeakPagedPoolUsage / 1024);
        printf("\tQuotaPagedPoolUsage: 0x%08X (%d)\n",
            _pmc.QuotaPagedPoolUsage, _pmc.QuotaPagedPoolUsage / 1024);
        printf("\tQuotaPeakNonPagedPoolUsage: 0x%08X (%d)\n",
            _pmc.QuotaPeakNonPagedPoolUsage, _pmc.QuotaPeakNonPagedPoolUsage / 1024);
        printf("\tQuotaNonPagedPoolUsage: 0x%08X (%d)\n",
            _pmc.QuotaNonPagedPoolUsage, _pmc.QuotaNonPagedPoolUsage / 1024);
        printf("\tPagefileUsage: 0x%08X (%d)\n", _pmc.PagefileUsage, _pmc.PagefileUsage / 1024);
        printf("\tPeakPagefileUsage: 0x%08X (%d)\n\n",
            _pmc.PeakPagefileUsage, _pmc.PeakPagefileUsage / 1024);
    }
private:
    PROCESS_MEMORY_COUNTERS _pmc;
};

int main(void)
{
    std::string search_query = "CHANGE ME";
    Process host_process{ "ProcHost.exe" };
 
    if (host_process.get()) {
        HostModule module(host_process);
        _tprintf(TEXT("FOUND: %s  (PID: %u) 0x%08X\n"), module.name(), host_process.id(), module.address());

        MemoryInfo(host_process).print();

        std::printf("Found '%s' at addresses:\n", search_query.c_str());
        auto addresses = get_addresses_of_memory_pattern_search(host_process.get(), search_query, std::ostream_iterator<void*>(std::cout, "\n"));
        std::printf("\nEnter text to replace '%s' with:\n", search_query.c_str());
        while (true) {
            std::string replacement_text;
            std::printf("> ");
            std::getline(std::cin, replacement_text);
            if (replacement_text.length() > search_query.length()) {
                std::printf("The entered text has %u characters, which is longer than the replaced text with length of %u characters\n", replacement_text.length(), search_query.length());
            }
            for (const auto address : addresses) {
                SIZE_T written;
                WriteProcessMemory(host_process.get(), (LPVOID)address, (LPCVOID)replacement_text.c_str(), sizeof(replacement_text), &written);
            }
        }
        
    }
    else {
        std::printf("NAY\n");
    }
    
    return 0;
}