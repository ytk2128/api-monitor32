#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <future>
#include <csignal>
#include <algorithm>
#include <unordered_map>
#include <sstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include "PE/PEBase.h"

using namespace std;
using namespace pe32;

namespace {
	bool threadExit;
}

typedef struct {
	WORD ordinal;
	size_t size;
	string name;
	vector<BYTE> code;
} Function;

typedef struct {
	string name;
	vector<Function> func;
} DLL;

typedef struct {
	string dll;
	using IATFunc = struct {
		string name;
		WORD ordinal;
		PBYTE pIAT;
		DWORD addr;
	};
	vector<IATFunc> func;
} IAT;

class Monitor {
public:
	Monitor(int pid, vector<string>& dlls)
		: _pid(pid)
		, _path()
		, _hProcess()
		, _dlls(dlls)
		, _workers()
		, _targetDLLs()
		, _loadedDLLs()
		, _importDLLs()
	{}

	~Monitor() {
		CloseHandle(_hProcess);
	}

	bool ready() {
		_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _pid);
		if (!(_hProcess && isRunning())) {
			return false;
		}

		MODULEENTRY32 me = {};
		shared_ptr<void> hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid), &CloseHandle);
		me.dwSize = sizeof(MODULEENTRY32);
		if (!(hSnapshot.get() != INVALID_HANDLE_VALUE && Module32First(hSnapshot.get(), &me))) {
			return false;
		}

		_path = me.szExePath;
		transform(_path.begin(), _path.end(), _path.begin(), tolower);
		
		while (Module32Next(hSnapshot.get(), &me)) {
			string module = me.szModule;
			transform(module.begin(), module.end(), module.begin(), tolower);
			_loadedDLLs[module] = 0;
		}

		for (auto& dll : _dlls) {
			transform(dll.begin(), dll.end(), dll.begin(), tolower);
			if (_loadedDLLs.find(dll) != _loadedDLLs.end()) {
				_targetDLLs.emplace_back();
				_targetDLLs.back().name = dll.c_str();
			}
		}

		threadExit = false;
		signal(SIGINT, [](int signal) {
			cout << "\n\nInterrupt occurred.\n";
			threadExit = true;
		});

		_workers.emplace_back([&]() {
			while (isRunning());
			threadExit = true;
		});
		_workers.back().detach();

		return true;
	}

	void start() {
		cout << "--API Monitor32--\n";
		cout << "-PID: " << _pid << "\n";
		cout << "-NAME: " << getNameFromPath(_path) << "\n";
		cout << "-PATH: " << _path << "\n\n\n";
		
		for (auto& dll : _targetDLLs) {
			auto r = async(&Monitor::analyzeFunctions, this, &dll);
			
			if (r.get()) {
				_workers.emplace_back(&Monitor::monitorFunctions, this, &dll);
				_workers.back().detach();
			}
		}

		auto r = async(&Monitor::analyzeIAT, this);
		if (!r.get()) {
			cerr << "Failed to analyze IAT.\n";
			threadExit = true;
			return;
		}

		for (auto& dll : _importDLLs) {
			_workers.emplace_back(&Monitor::monitorIAT, this, &dll);
			_workers.back().detach();
		}
	}

private:
	bool analyzeFunctions(DLL* dll) const {
		auto* mem = (PBYTE)LoadLibrary(dll->name.c_str());
		if (!mem) {
			return false;
		}
		
		auto* pDosHeader = (PIMAGE_DOS_HEADER)mem;
		auto* pNtHeader = (PIMAGE_NT_HEADERS)(mem + pDosHeader->e_lfanew);
		auto* pExport = (PIMAGE_EXPORT_DIRECTORY)(mem + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

		dll->func.resize(pExport->NumberOfFunctions);
		auto* pAddressOfNames = (PDWORD)(mem + pExport->AddressOfNames);
		auto* pOrdinal = (PWORD)(mem + pExport->AddressOfNameOrdinals);
		
		for (auto i = 0; i != pExport->NumberOfNames; i++) {
			dll->func[pOrdinal[i]].name = (char*)(mem + pAddressOfNames[i]);
		}

		for (auto i = 0; i != pExport->NumberOfFunctions; i++) {
			dll->func[i].ordinal = (WORD)(i + pExport->Base);

			auto* pFunc = (PDWORD)GetProcAddress((HMODULE)mem, dll->func[i].name.empty() ?
				(LPCSTR)dll->func[i].ordinal : dll->func[i].name.c_str());
			if (pFunc) {
				dll->func[i].size = 0;
				
				for (auto* k = (PBYTE)pFunc; *(PDWORD64)k && *(PWORD)k != 0xCCCC; k++) {
					dll->func[i].code.push_back(*k);
					dll->func[i].size++;
				}
			}
		}

		return true;
	}

	void monitorFunctions(DLL* dll) const {
		auto* mem = (PBYTE)LoadLibrary(dll->name.c_str());
		if (!mem) {
			return;
		}
		
		while (!threadExit) {
			for (auto& func : dll->func) {
				if (!func.name.compare("gSharedInfo")) {
					continue;
				}

				auto* pFunc = (PDWORD)GetProcAddress((HMODULE)mem, func.name.empty() ?
					(LPCSTR)func.ordinal : func.name.c_str());
				if (pFunc) {
					vector<BYTE> code(func.size);
					if (readMemory(pFunc, &code[0], func.size)) {
						if (memcmp(&code[0], &func.code[0], func.size)) {
							writeMemory(pFunc, &func.code[0], func.size);

							DWORD fidx = 0;
							DWORD cnt = 0;
							for (; code[fidx] == func.code[fidx]; fidx++);
							for (auto i = fidx; i < code.size(); i++) {
								if (code[i] != func.code[i]) {
									cnt++;
								}
							}

							auto funcName = func.name.empty() ? format("ordinal:%04X", func.ordinal) : func.name;
							stringstream output;
							output << format("modified-function: %s (%08X)\n",
								funcName.c_str(),
								(DWORD)pFunc);

							output << format("address: %s+%X (%08X)\n",
								dll->name.c_str(),
								(DWORD)pFunc - (DWORD)mem + fidx,
								(DWORD)pFunc + fidx);

							if (code[fidx] == 0xE9) {
								auto redir = *(PDWORD)&code[fidx + 1];
								redir += (DWORD)pFunc + fidx + 5;
								output << format("type: inline hook (%d bytes)\n", cnt);
								output << format("\t%s (%08X) => ",
									funcName.c_str(),
									(DWORD)pFunc);
								pair<string, DWORD> module;
								if (getModule(redir, module)) {
									output << format("%s+%X (%08X)\n",
										module.first.c_str(),
										redir - module.second,
										redir);
								}
								else {
									output << format("%08X\n", redir);
								}
							}
							else if (code[fidx] == 0xC3) {
								output << format("type: return (%d bytes)\n", cnt);
							}
							else if (code[fidx] == 0xC2) {
								output << format("type: return %X (%d bytes)\n",
									*(PWORD)&code[fidx + 1],
									cnt);
							}
							else {
								output << format("type: custom patch (%d bytes)\n", cnt);
							}
							cout << output.str() << "\n";
						}
					}
				}
			}
		}
	}

public:
	bool analyzeIAT() {
		MODULEENTRY32 me = {};
		shared_ptr<void> hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid), &CloseHandle);
		me.dwSize = sizeof(MODULEENTRY32);
		if (!(hSnapshot.get() != INVALID_HANDLE_VALUE && Module32First(hSnapshot.get(), &me))) {
			return false;
		}

		auto* imagebase = me.modBaseAddr;
		PEFile file(me.szExePath);
		if (!file.ImportDirectory->VirtualAddress) {
			return false;
		}

		auto* pIID = (PIMAGE_IMPORT_DESCRIPTOR)(file.data() + file.rvaToRaw(file.ImportDirectory->VirtualAddress));
		for (; pIID->FirstThunk; pIID++) {
			string dll = (LPCSTR)(file.data() + file.rvaToRaw(pIID->Name));
			transform(dll.begin(), dll.end(), dll.begin(), tolower);
			auto* module = (PBYTE)LoadLibrary(dll.c_str());
			if (!module) {
				continue;
			}

			auto compare = [&](const DLL& i) {
				return !dll.compare(i.name);
			};

			if (find_if(_targetDLLs.begin(), _targetDLLs.end(), compare) == _targetDLLs.end()) {
				continue;
			}

			_importDLLs.emplace_back();
			_importDLLs.back().dll = dll.c_str();

			auto* origFirstThunk = (PIMAGE_THUNK_DATA)(file.data() + file.rvaToRaw(pIID->OriginalFirstThunk));
			auto* firstThunk = (PIMAGE_THUNK_DATA)(file.data() + file.rvaToRaw(pIID->FirstThunk));
			
			for (; origFirstThunk->u1.AddressOfData; origFirstThunk++, firstThunk++) {
				_importDLLs.back().func.emplace_back();

				LPCSTR lpProcName;
				if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					_importDLLs.back().func.back().ordinal = origFirstThunk->u1.Ordinal & 0xFFFF;
					lpProcName = (LPCSTR)(_importDLLs.back().func.back().ordinal);
				}
				else {
					lpProcName = (LPCSTR)(file.data() + file.rvaToRaw(origFirstThunk->u1.AddressOfData) + 2);
					_importDLLs.back().func.back().name = lpProcName;
				}
				
				auto* pFunc = (PDWORD)GetProcAddress((HMODULE)module, lpProcName);
				if (!pFunc) {
					continue;
				}

				_importDLLs.back().func.back().addr = (DWORD)pFunc;
				_importDLLs.back().func.back().pIAT = imagebase + file.rawToRva((DWORD)(&(firstThunk->u1.Function)) - (DWORD)file.data());
			}
		}

		return true;
	}

	void monitorIAT(IAT* iat) const {
		while (!threadExit) {
			for (auto& func : iat->func) {
				DWORD addr = 0;
				if (readMemory(func.pIAT, &addr, sizeof(DWORD))) {
					if (addr != func.addr) {
						writeMemory(func.pIAT, &func.addr, sizeof(DWORD));
						
						auto funcName = func.name.empty() ? format("ordinal:%04X", func.ordinal) : func.name;
						stringstream output;
						output << format("modified-function: %s (%08X)\n",
							funcName.c_str(),
							func.addr);
						
						output << format("address: %08X (IAT)\n", (DWORD)func.pIAT);
						output << "type: IAT hook\n" << format("\t%s (%08X) => ",
							funcName.c_str(),
							func.addr);

						pair<string, DWORD> module;
						if (getModule(addr, module)) {
							output << format("%s+%X (%08X)\n",
								module.first.c_str(),
								addr - module.second,
								addr);
						}
						else {
							output << format("%08X\n", addr);
						}
						cout << output.str() << "\n";
					}
				}
			}
		}
	}

private:
	bool isRunning() const {
		DWORD dwExitCode;
		GetExitCodeProcess(_hProcess, &dwExitCode);
		return dwExitCode == STILL_ACTIVE;
	}

	bool getModule(DWORD address, pair<string, DWORD>& module) const {
		MODULEENTRY32 me = {};
		shared_ptr<void> hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid), &CloseHandle);
		me.dwSize = sizeof(MODULEENTRY32);
		if (!(hSnapshot.get() != INVALID_HANDLE_VALUE && Module32First(hSnapshot.get(), &me))) {
			return false;
		}

		while (Module32Next(hSnapshot.get(), &me)) {
			if (address <= (DWORD)me.modBaseAddr + me.modBaseSize && address >= (DWORD)me.modBaseAddr) {
				module.first = me.szModule;
				transform(module.first.begin(), module.first.end(), module.first.begin(), tolower);
				module.second = (DWORD)me.modBaseAddr;
				return true;
			}
		}
		
		return false;
	}

	bool __stdcall readMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) const {
		DWORD flOldProtect;
		return VirtualProtectEx(_hProcess, (LPVOID)lpBaseAddress, nSize, PAGE_EXECUTE_READ, &flOldProtect) &&
			ReadProcessMemory(_hProcess, lpBaseAddress, lpBuffer, nSize, NULL) &&
			VirtualProtectEx(_hProcess, (LPVOID)lpBaseAddress, nSize, flOldProtect, &flOldProtect);
	}

	bool __stdcall writeMemory(LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) const {
		DWORD flOldProtect;
		return VirtualProtectEx(_hProcess, lpBaseAddress, nSize, PAGE_EXECUTE_READWRITE, &flOldProtect) &&
			WriteProcessMemory(_hProcess, lpBaseAddress, lpBuffer, nSize, NULL) &&
			VirtualProtectEx(_hProcess, lpBaseAddress, nSize, flOldProtect, &flOldProtect);
	}

	string format(const char* str, ...) const {
		char buf[1024] = {};
		va_list ap;
		va_start(ap, str);
		StringCbVPrintf(buf, sizeof(buf), str, ap);
		va_end(ap);
		return buf;
	}

	inline string getNameFromPath(const string& path) const {
		return path.substr(path.find_last_of("\\") + 1);
	}

private:
	int _pid;
	string _path;
	HANDLE _hProcess;
	vector<string> _dlls;
	vector<thread> _workers;
	vector<DLL> _targetDLLs;
	unordered_map<string, int> _loadedDLLs;
	vector<IAT> _importDLLs;
};