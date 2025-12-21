#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma comment(lib, "shlwapi.lib")

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

// 查找指定名称的进程并返回句柄
HANDLE FindProcessByName(const wchar_t* processName, DWORD* outPid = nullptr) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    HANDLE hProcess = nullptr;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                if (hProcess && outPid) {
                    *outPid = pe32.th32ProcessID;
                }
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return hProcess;
}

// 获取进程主窗口句柄
HWND GetMainWindowHandle(DWORD processId) {
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
}

// 检查进程是否还在运行
bool IsProcessRunning(HANDLE hProcess) {
    DWORD exitCode;
    return GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
}

int wmain() {
    std::locale::global(std::locale("zh_CN.UTF-8"));
    std::wcout.imbue(std::locale("zh_CN.UTF-8"));

    // 获取启动器路径
    wchar_t launcherExePath[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherExePath, MAX_PATH);
    std::wstring launcherPath = launcherExePath;
    std::wstring launcherDir = launcherPath.substr(0, launcherPath.find_last_of(L"\\/"));
    std::wstring iniPath = launcherPath.substr(0, launcherPath.find_last_of(L'.')) + L".ini";

    // 读取配置
    wchar_t targetExe[MAX_PATH] = { 0 };
    GetPrivateProfileStringW(L"Settings", L"TargetExe", L"release.public.exe", targetExe, MAX_PATH, iniPath.c_str());

    wchar_t betterGIUri[256] = { 0 };
    GetPrivateProfileStringW(L"Settings", L"BetterGI", L"", betterGIUri, 256, iniPath.c_str());

    bool autoCloseBetterGI = GetPrivateProfileIntW(L"Settings", L"AutoCloseBetterGI", 1, iniPath.c_str()) != 0;

    // 构建目标可执行文件路径
    std::wstring targetPath = launcherDir + L"\\" + targetExe;

    // 检查目标文件是否存在
    if (!PathFileExistsW(targetPath.c_str())) {
        std::wcerr << L"[-] 找不到目标程序: " << targetPath << std::endl;
        std::wcerr << L"[-] 请确保 " << targetExe << L" 与 DroneLauncher.exe 在同一目录" << std::endl;
        system("pause");
        return 1;
    }

    std::wcout << L"[+] 正在启动: " << targetPath << std::endl;

    // 启动目标程序
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.lpFile = targetPath.c_str();
    sei.lpDirectory = launcherDir.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei) || sei.hProcess == nullptr) {
        std::wcerr << L"[-] 启动目标程序失败" << std::endl;
        system("pause");
        return 1;
    }

    std::wcout << L"[+] 目标程序已启动" << std::endl;
    CloseHandle(sei.hProcess);  // 我们不需要跟踪这个进程，而是跟踪游戏进程

    // 如果没有配置 BetterGI，直接退出
    if (wcslen(betterGIUri) == 0) {
        std::wcout << L"[*] 未配置 BetterGI，启动完成" << std::endl;
        return 0;
    }

    std::wcout << L"[+] 等待游戏进程..." << std::endl;

    // 等待游戏进程出现
    HANDLE hGameProcess = nullptr;
    DWORD gamePid = 0;
    int waitCount = 0;
    const int maxWaitSeconds = 120;  // 最多等待120秒

    while (waitCount < maxWaitSeconds * 10) {  // 每100ms检查一次
        hGameProcess = FindProcessByName(L"YuanShen.exe", &gamePid);
        if (hGameProcess != nullptr) {
            break;
        }
        Sleep(100);
        waitCount++;
    }

    if (hGameProcess == nullptr) {
        std::wcerr << L"[-] 等待游戏进程超时" << std::endl;
        return 1;
    }

    std::wcout << L"[+] 检测到游戏进程 (PID: " << gamePid << L")" << std::endl;
    std::wcout << L"[+] 等待游戏窗口..." << std::endl;

    // 等待游戏窗口出现
    bool betterGILaunched = false;
    while (IsProcessRunning(hGameProcess)) {
        HWND mainWindow = GetMainWindowHandle(gamePid);
        if (mainWindow != nullptr) {
            std::wcout << L"[+] 正在启动 BetterGI: " << betterGIUri << std::endl;
            ShellExecuteW(nullptr, L"open", betterGIUri, nullptr, nullptr, SW_SHOWNORMAL);
            betterGILaunched = true;
            break;
        }
        Sleep(10);
    }

    // 监控游戏进程，游戏关闭时关闭 BetterGI
    if (betterGILaunched && autoCloseBetterGI) {
        std::wcout << L"[+] 正在监控游戏进程，游戏关闭时将自动关闭 BetterGI..." << std::endl;

        // 隐藏控制台窗口
        ShowWindow(GetConsoleWindow(), SW_HIDE);

        // 等待游戏进程退出
        WaitForSingleObject(hGameProcess, INFINITE);

        std::wcout << L"[+] 游戏已关闭，正在关闭 BetterGI..." << std::endl;
        if (TerminateProcessByName(L"BetterGI.exe")) {
            std::wcout << L"[+] BetterGI 已关闭" << std::endl;
        } else {
            std::wcout << L"[*] BetterGI 未在运行或已关闭" << std::endl;
        }
    }

    CloseHandle(hGameProcess);
    return 0;
}
