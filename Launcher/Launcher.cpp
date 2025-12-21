#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")

// 查找并终止指定名称的进程
bool TerminateProcessByName(const wchar_t* processName) {
    bool terminated = false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess != nullptr) {
                    if (TerminateProcess(hProcess, 0)) {
                        terminated = true;
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return terminated;
}

bool InjectDll(HANDLE hProcess, const std::wstring& dllPath) {
    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibrary) return false;
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLibrary, remoteMem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    return true;
}

std::wstring OpenGameFileDialog() {
    wchar_t filePath[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.lpstrFilter = L"原神游戏本体 (YuanShen.exe;GenshinImpact.exe)\0YuanShen.exe;GenshinImpact.exe\0所有文件\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"请选择 GenshinImpact 或 YuanShen.exe";
    if (GetOpenFileNameW(&ofn)) {
        return filePath;
    }
    return L"";
}

int wmain() {
    std::locale::global(std::locale("zh_CN.UTF-8"));
    std::wcout.imbue(std::locale("zh_CN.UTF-8"));
    wchar_t launcherExePath[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherExePath, MAX_PATH);
    std::wstring launcherPath = launcherExePath;
    std::wstring launcherDir = launcherPath.substr(0, launcherPath.find_last_of(L"\\/"));
    std::wstring iniPath = launcherPath.substr(0, launcherPath.find_last_of(L'.')) + L".ini";
    wchar_t gameExePath[MAX_PATH] = { 0 };
    GetPrivateProfileStringW(L"Settings", L"GamePath", L"", gameExePath, MAX_PATH, iniPath.c_str());
    std::wstring gamePath = gameExePath;

    // 读取 BetterGI 启动 URI 配置 (例如: bettergi://start 或 bettergi://startOneDragon)
    wchar_t betterGIUri[256] = { 0 };
    GetPrivateProfileStringW(L"Settings", L"BetterGI", L"", betterGIUri, 256, iniPath.c_str());

    // 读取 AutoCloseBetterGI 配置 (默认启用)
    bool autoCloseBetterGI = GetPrivateProfileIntW(L"Settings", L"AutoCloseBetterGI", 1, iniPath.c_str()) != 0;
    if (gamePath.empty() || !PathFileExistsW(gamePath.c_str())) {
        std::wcout << L"[+] 请选择游戏文件..." << std::endl;
        gamePath = OpenGameFileDialog();
        if (gamePath.empty()) {
            std::wcerr << L"[-] 用户取消选择" << std::endl;
            system("pause");
            return 1;
        }
        WritePrivateProfileStringW(L"Settings", L"GamePath", gamePath.c_str(), iniPath.c_str());
    }
    std::wstring workingDir = gamePath.substr(0, gamePath.find_last_of(L"\\/"));
    std::wstring dllPath = launcherDir + L"\\Genshin.Fps.UnlockerIsland.dll";
    if (!PathFileExistsW(dllPath.c_str())) {
        std::wcerr << L"[-] 找不到 Genshin.Fps.UnlockerIsland.dll 文件,请确保文件完整" << std::endl;
        system("pause");
        return 1;
    }
    std::wcout << L"[+] 游戏路径: " << gamePath << std::endl;
    std::wcout << L"[+] DLL路径: " << dllPath << std::endl;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(
        gamePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        workingDir.c_str(),
        &si,
        &pi))
    {
        std::wcerr << L"[-] 无法创建游戏进程: " << gamePath << std::endl;
        system("pause");
        return 1;
    }
    if (!InjectDll(pi.hProcess, dllPath)) {
        std::wcerr << L"[-] 注入 DLL 失败。" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        system("pause");
        return 1;
    }
    ResumeThread(pi.hThread);
    std::wcout << L"[+] 游戏已启动并成功注入" << std::endl;

    // 启动 BetterGI (如果配置了 URI)
    // 参考胡桃的做法：检查进程是否在运行，然后等待主窗口句柄出现
    bool betterGILaunched = false;
    if (wcslen(betterGIUri) > 0) {
        std::wcout << L"[+] 等待游戏窗口..." << std::endl;

        // 获取进程主窗口句柄的 lambda (类似 .NET Process.MainWindowHandle)
        auto getMainWindowHandle = [](DWORD processId) -> HWND {
            struct EnumData { DWORD pid; HWND hwnd; } data = { processId, nullptr };
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* d = reinterpret_cast<EnumData*>(lParam);
                DWORD pid;
                GetWindowThreadProcessId(hwnd, &pid);
                if (pid == d->pid && IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == nullptr) {
                    d->hwnd = hwnd;
                    return FALSE;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&data));
            return data.hwnd;
        };

        // 检查进程是否还在运行 (类似胡桃的 IsRunning = !HasExited)
        auto isRunning = [](HANDLE hProcess) -> bool {
            DWORD exitCode;
            return GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
        };

        // SpinWait 等待主窗口句柄出现 (类似胡桃的 SpinWaitPolyfill.SpinUntil)
        while (isRunning(pi.hProcess)) {
            HWND mainWindow = getMainWindowHandle(pi.dwProcessId);
            if (mainWindow != nullptr) {
                std::wcout << L"[+] 正在启动 BetterGI: " << betterGIUri << std::endl;
                ShellExecuteW(nullptr, L"open", betterGIUri, nullptr, nullptr, SW_SHOWNORMAL);
                betterGILaunched = true;
                break;
            }
            Sleep(10);  // SpinOnce - 让出 CPU 时间片
        }

        // 实时监控：等待原神关闭，然后同步关闭 BetterGI
        if (betterGILaunched && autoCloseBetterGI) {
            std::wcout << L"[+] 正在监控游戏进程，游戏关闭时将自动关闭 BetterGI..." << std::endl;

            // 隐藏控制台窗口
            ShowWindow(GetConsoleWindow(), SW_HIDE);

            // 等待原神进程退出
            WaitForSingleObject(pi.hProcess, INFINITE);

            std::wcout << L"[+] 游戏已关闭，正在关闭 BetterGI..." << std::endl;
            if (TerminateProcessByName(L"BetterGI.exe")) {
                std::wcout << L"[+] BetterGI 已关闭" << std::endl;
            } else {
                std::wcout << L"[*] BetterGI 未在运行或已关闭" << std::endl;
            }
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
