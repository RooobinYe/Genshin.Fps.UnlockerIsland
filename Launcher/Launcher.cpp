#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// 常量定义
// ============================================================================
const wchar_t* MAPPING_NAME = L"4F3E8543-40F7-4808-82DC-21E48A6037A7";
const int UDP_PORT = 12345;
const char* UDP_HOST = "127.0.0.1";

// ============================================================================
// 共享内存结构（与 nvhelper.dll 一致）
// ============================================================================
struct HookFunctionOffsets {
    DWORD Hook_GameManagerAwake;
    DWORD Hook_MainEntryPoint;
    DWORD Hook_MainEntryPartner1;
    DWORD Hook_MainEntryPartner2;
    DWORD Hook_SetUid;
    DWORD Hook_SetFov;
    DWORD Hook_SetFog;
    DWORD Hook_GetFps;
    DWORD Hook_SetFps;
    DWORD Hook_OpenTeam;
    DWORD Hook_OpenTeamAdvanced;
    DWORD Hook_CheckEnter;
    DWORD Hook_QuestBanner;
    DWORD Hook_FindObject;
    DWORD Hook_ObjectActive;
    DWORD Hook_CameraMove;
    DWORD Hook_DamageText;
    DWORD Hook_TouchInput;
    DWORD Hook_CombineEntry;
    DWORD Hook_CombineEntryPartner;
    DWORD Hook_SetupResin;
    DWORD Hook_ResinList;
    DWORD Hook_ResinCount;
    DWORD Hook_ResinItem;
    DWORD Hook_ResinRemove;
};

struct HookEnvironment {
    DWORD Size;
    DWORD State;
    DWORD LastError;
    DWORD Uid;
    HookFunctionOffsets Offsets;
    BOOL  EnableSetFov;
    FLOAT FieldOfView;
    BOOL  FixLowFov;
    BOOL  DisableFog;
    BOOL  EnableSetFps;
    DWORD TargetFps;
    BOOL  RemoveTeamProgress;
    BOOL  HideQuestBanner;
    BOOL  DisableCameraMove;
    BOOL  DisableDamageText;
    BOOL  TouchMode;
    BOOL  RedirectCombine;
    BOOL  ResinItem000106;
    BOOL  ResinItem000201;
    BOOL  ResinItem107009;
    BOOL  ResinItem107012;
    BOOL  ResinItem220007;
};

// ============================================================================
// 配置结构
// ============================================================================
struct LauncherConfig {
    // [Settings]
    std::wstring gamePath;
    std::wstring betterGIUri;
    bool autoCloseBetterGI = true;

    // [Visual] - 运行时通过 UDP 配置
    bool enableFpsOverride = true;
    int selectedFps = 60;
    bool enableFovOverride = false;
    float fovValue = 45.0f;
    bool enableFogOverride = false;
    bool enablePerspectiveOverride = false;

    // [Features] - 注入时通过共享内存配置
    bool hideQuestBanner = false;        // 隐藏横幅广告 (0=显示, 1=隐藏)
    bool disableDamageText = false;      // 隐藏伤害文本 (0=显示, 1=隐藏)
    bool touchMode = false;              // 触屏UI
    bool disableEventCameraMove = false; // 去除元素爆发镜头
    bool removeTeamProgress = false;     // 去除配队进度条
    bool redirectCombine = false;        // 随时合成台
};

// ============================================================================
// 全局变量
// ============================================================================
LauncherConfig g_config;
LauncherConfig g_lastConfig;  // 用于检测配置变化
std::wstring g_iniPath;
std::atomic<bool> g_running(true);
HANDLE g_hMapping = nullptr;
HookEnvironment* g_pEnv = nullptr;
SOCKET g_udpSocket = INVALID_SOCKET;

// ============================================================================
// 辅助函数
// ============================================================================
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

// ============================================================================
// 配置读取
// ============================================================================
void LoadConfig() {
    wchar_t buffer[MAX_PATH] = { 0 };

    // [Settings]
    GetPrivateProfileStringW(L"Settings", L"GamePath", L"", buffer, MAX_PATH, g_iniPath.c_str());
    g_config.gamePath = buffer;

    GetPrivateProfileStringW(L"Settings", L"BetterGI", L"", buffer, MAX_PATH, g_iniPath.c_str());
    g_config.betterGIUri = buffer;

    g_config.autoCloseBetterGI = GetPrivateProfileIntW(L"Settings", L"AutoCloseBetterGI", 1, g_iniPath.c_str()) != 0;

    // [Visual] - 运行时 UDP 配置
    g_config.enableFpsOverride = GetPrivateProfileIntW(L"Visual", L"EnableFpsOverride", 1, g_iniPath.c_str()) != 0;
    g_config.selectedFps = GetPrivateProfileIntW(L"Visual", L"SelectedFps", 60, g_iniPath.c_str());
    g_config.enableFovOverride = GetPrivateProfileIntW(L"Visual", L"EnableFovOverride", 0, g_iniPath.c_str()) != 0;

    wchar_t fovStr[32] = { 0 };
    GetPrivateProfileStringW(L"Visual", L"FovValue", L"45.0", fovStr, 32, g_iniPath.c_str());
    g_config.fovValue = static_cast<float>(_wtof(fovStr));

    g_config.enableFogOverride = GetPrivateProfileIntW(L"Visual", L"EnableFogOverride", 0, g_iniPath.c_str()) != 0;
    g_config.enablePerspectiveOverride = GetPrivateProfileIntW(L"Visual", L"EnablePerspectiveOverride", 0, g_iniPath.c_str()) != 0;

    // [Features] - 启动时共享内存配置
    g_config.hideQuestBanner = GetPrivateProfileIntW(L"Features", L"HideQuestBanner", 0, g_iniPath.c_str()) != 0;
    g_config.disableDamageText = GetPrivateProfileIntW(L"Features", L"DisableDamageText", 0, g_iniPath.c_str()) != 0;
    g_config.touchMode = GetPrivateProfileIntW(L"Features", L"TouchMode", 0, g_iniPath.c_str()) != 0;
    g_config.disableEventCameraMove = GetPrivateProfileIntW(L"Features", L"DisableEventCameraMove", 0, g_iniPath.c_str()) != 0;
    g_config.removeTeamProgress = GetPrivateProfileIntW(L"Features", L"RemoveTeamProgress", 0, g_iniPath.c_str()) != 0;
    g_config.redirectCombine = GetPrivateProfileIntW(L"Features", L"RedirectCombine", 0, g_iniPath.c_str()) != 0;
}

void SaveDefaultConfig() {
    // [Settings]
    if (g_config.gamePath.empty()) {
        WritePrivateProfileStringW(L"Settings", L"GamePath", L"", g_iniPath.c_str());
    }
    WritePrivateProfileStringW(L"Settings", L"BetterGI", L"", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Settings", L"AutoCloseBetterGI", L"1", g_iniPath.c_str());

    // [Visual]
    WritePrivateProfileStringW(L"Visual", L"EnableFpsOverride", L"1", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Visual", L"SelectedFps", L"60", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Visual", L"EnableFovOverride", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Visual", L"FovValue", L"45.0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Visual", L"EnableFogOverride", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Visual", L"EnablePerspectiveOverride", L"0", g_iniPath.c_str());

    // [Features]
    WritePrivateProfileStringW(L"Features", L"HideQuestBanner", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Features", L"DisableDamageText", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Features", L"TouchMode", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Features", L"DisableEventCameraMove", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Features", L"RemoveTeamProgress", L"0", g_iniPath.c_str());
    WritePrivateProfileStringW(L"Features", L"RedirectCombine", L"0", g_iniPath.c_str());
}

// ============================================================================
// 共享内存管理
// ============================================================================
bool InitSharedMemory() {
    g_hMapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, MAPPING_NAME);
    if (g_hMapping == nullptr) {
        g_hMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(HookEnvironment), MAPPING_NAME);
    }

    if (g_hMapping == nullptr) {
        std::wcerr << L"[-] 无法创建共享内存" << std::endl;
        return false;
    }

    g_pEnv = (HookEnvironment*)MapViewOfFile(g_hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(HookEnvironment));
    if (g_pEnv == nullptr) {
        std::wcerr << L"[-] 无法映射共享内存" << std::endl;
        CloseHandle(g_hMapping);
        g_hMapping = nullptr;
        return false;
    }

    return true;
}

void UpdateSharedMemory() {
    if (g_pEnv == nullptr) return;

    g_pEnv->Size = sizeof(HookEnvironment);

    // Visual 配置（也写入共享内存作为初始值）
    g_pEnv->EnableSetFps = g_config.enableFpsOverride ? TRUE : FALSE;
    g_pEnv->TargetFps = g_config.selectedFps;
    g_pEnv->EnableSetFov = g_config.enableFovOverride ? TRUE : FALSE;
    g_pEnv->FieldOfView = g_config.fovValue;
    g_pEnv->DisableFog = g_config.enableFogOverride ? TRUE : FALSE;

    // Features 配置
    g_pEnv->HideQuestBanner = g_config.hideQuestBanner ? TRUE : FALSE;
    g_pEnv->DisableDamageText = g_config.disableDamageText ? TRUE : FALSE;
    g_pEnv->TouchMode = g_config.touchMode ? TRUE : FALSE;
    g_pEnv->DisableCameraMove = g_config.disableEventCameraMove ? TRUE : FALSE;
    g_pEnv->RemoveTeamProgress = g_config.removeTeamProgress ? TRUE : FALSE;
    g_pEnv->RedirectCombine = g_config.redirectCombine ? TRUE : FALSE;

    std::wcout << L"[+] 共享内存已更新" << std::endl;
}

void CleanupSharedMemory() {
    if (g_pEnv != nullptr) {
        UnmapViewOfFile(g_pEnv);
        g_pEnv = nullptr;
    }
    if (g_hMapping != nullptr) {
        CloseHandle(g_hMapping);
        g_hMapping = nullptr;
    }
}

// ============================================================================
// UDP 通信
// ============================================================================
bool InitUDP() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::wcerr << L"[-] WSAStartup 失败" << std::endl;
        return false;
    }

    g_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udpSocket == INVALID_SOCKET) {
        std::wcerr << L"[-] 创建 UDP socket 失败" << std::endl;
        WSACleanup();
        return false;
    }

    // 设置超时
    DWORD timeout = 1000;
    setsockopt(g_udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    return true;
}

bool SendUDPCommand(const std::string& command) {
    if (g_udpSocket == INVALID_SOCKET) return false;

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(UDP_PORT);
    inet_pton(AF_INET, UDP_HOST, &serverAddr.sin_addr);

    int sent = sendto(g_udpSocket, command.c_str(), (int)command.length(), 0,
        (sockaddr*)&serverAddr, sizeof(serverAddr));

    if (sent == SOCKET_ERROR) {
        return false;
    }

    // 尝试接收响应
    char buffer[256] = { 0 };
    sockaddr_in fromAddr = {};
    int fromLen = sizeof(fromAddr);
    int received = recvfrom(g_udpSocket, buffer, sizeof(buffer) - 1, 0,
        (sockaddr*)&fromAddr, &fromLen);

    if (received > 0) {
        buffer[received] = '\0';
        return (strcmp(buffer, "OK") == 0 || strcmp(buffer, "alive") == 0);
    }

    return false;
}

void SendAllUDPConfig() {
    // FPS
    SendUDPCommand(g_config.enableFpsOverride ? "enable_fps_override" : "disable_fps_override");
    SendUDPCommand("set_fps " + std::to_string(g_config.selectedFps));

    // FOV
    SendUDPCommand(g_config.enableFovOverride ? "enable_fov_override" : "disable_fov_override");
    char fovCmd[64];
    sprintf_s(fovCmd, "set_fov %.1f", g_config.fovValue);
    SendUDPCommand(fovCmd);

    // 雾
    SendUDPCommand(g_config.enableFogOverride ? "enable_display_fog_override" : "disable_display_fog_override");

    // 视角覆盖
    SendUDPCommand(g_config.enablePerspectiveOverride ? "enable_Perspective_override" : "disable_Perspective_override");

    std::wcout << L"[+] UDP 配置已发送" << std::endl;
}

void CleanupUDP() {
    if (g_udpSocket != INVALID_SOCKET) {
        closesocket(g_udpSocket);
        g_udpSocket = INVALID_SOCKET;
    }
    WSACleanup();
}

// ============================================================================
// 配置变化检测和应用
// ============================================================================
bool ConfigChanged() {
    return g_config.enableFpsOverride != g_lastConfig.enableFpsOverride ||
        g_config.selectedFps != g_lastConfig.selectedFps ||
        g_config.enableFovOverride != g_lastConfig.enableFovOverride ||
        g_config.fovValue != g_lastConfig.fovValue ||
        g_config.enableFogOverride != g_lastConfig.enableFogOverride ||
        g_config.enablePerspectiveOverride != g_lastConfig.enablePerspectiveOverride;
}

void ApplyConfigChanges() {
    // FPS 变化
    if (g_config.enableFpsOverride != g_lastConfig.enableFpsOverride) {
        SendUDPCommand(g_config.enableFpsOverride ? "enable_fps_override" : "disable_fps_override");
        std::wcout << L"[*] FPS覆盖: " << (g_config.enableFpsOverride ? L"开启" : L"关闭") << std::endl;
    }
    if (g_config.selectedFps != g_lastConfig.selectedFps) {
        SendUDPCommand("set_fps " + std::to_string(g_config.selectedFps));
        std::wcout << L"[*] FPS: " << g_config.selectedFps << std::endl;
    }

    // FOV 变化
    if (g_config.enableFovOverride != g_lastConfig.enableFovOverride) {
        SendUDPCommand(g_config.enableFovOverride ? "enable_fov_override" : "disable_fov_override");
        std::wcout << L"[*] FOV覆盖: " << (g_config.enableFovOverride ? L"开启" : L"关闭") << std::endl;
    }
    if (g_config.fovValue != g_lastConfig.fovValue) {
        char fovCmd[64];
        sprintf_s(fovCmd, "set_fov %.1f", g_config.fovValue);
        SendUDPCommand(fovCmd);
        std::wcout << L"[*] FOV: " << g_config.fovValue << std::endl;
    }

    // 雾变化
    if (g_config.enableFogOverride != g_lastConfig.enableFogOverride) {
        SendUDPCommand(g_config.enableFogOverride ? "enable_display_fog_override" : "disable_display_fog_override");
        std::wcout << L"[*] 去雾: " << (g_config.enableFogOverride ? L"开启" : L"关闭") << std::endl;
    }

    // 视角覆盖变化
    if (g_config.enablePerspectiveOverride != g_lastConfig.enablePerspectiveOverride) {
        SendUDPCommand(g_config.enablePerspectiveOverride ? "enable_Perspective_override" : "disable_Perspective_override");
        std::wcout << L"[*] 视角覆盖: " << (g_config.enablePerspectiveOverride ? L"开启" : L"关闭") << std::endl;
    }

    g_lastConfig = g_config;
}

// ============================================================================
// INI 文件监控线程
// ============================================================================
void FileMonitorThread() {
    FILETIME lastWriteTime = { 0 };

    // 获取初始文件时间
    HANDLE hFile = CreateFileW(g_iniPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        GetFileTime(hFile, nullptr, nullptr, &lastWriteTime);
        CloseHandle(hFile);
    }

    std::wcout << L"[+] INI 文件监控已启动" << std::endl;

    while (g_running) {
        Sleep(500);  // 每 500ms 检查一次

        hFile = CreateFileW(g_iniPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        FILETIME currentWriteTime;
        if (GetFileTime(hFile, nullptr, nullptr, &currentWriteTime)) {
            if (CompareFileTime(&currentWriteTime, &lastWriteTime) != 0) {
                lastWriteTime = currentWriteTime;
                CloseHandle(hFile);

                // 等待文件写入完成
                Sleep(100);

                std::wcout << L"[*] 检测到配置文件变化，重新加载..." << std::endl;
                LoadConfig();

                if (ConfigChanged()) {
                    ApplyConfigChanges();
                }

                continue;
            }
        }
        CloseHandle(hFile);
    }
}

// ============================================================================
// 主函数
// ============================================================================
int wmain() {
    std::locale::global(std::locale("zh_CN.UTF-8"));
    std::wcout.imbue(std::locale("zh_CN.UTF-8"));

    std::wcout << L"========================================" << std::endl;
    std::wcout << L"  原神启动器 (nvhelper.dll 版本)" << std::endl;
    std::wcout << L"========================================" << std::endl;

    // 获取路径
    wchar_t launcherExePath[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherExePath, MAX_PATH);
    std::wstring launcherPath = launcherExePath;
    std::wstring launcherDir = launcherPath.substr(0, launcherPath.find_last_of(L"\\/"));
    g_iniPath = launcherPath.substr(0, launcherPath.find_last_of(L'.')) + L".ini";

    // 检查 INI 文件是否存在，不存在则创建默认配置
    if (GetFileAttributesW(g_iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[+] 创建默认配置文件..." << std::endl;
        SaveDefaultConfig();
    }

    // 加载配置
    LoadConfig();
    g_lastConfig = g_config;

    // 检查游戏路径
    if (g_config.gamePath.empty() || !PathFileExistsW(g_config.gamePath.c_str())) {
        std::wcout << L"[+] 请选择游戏文件..." << std::endl;
        g_config.gamePath = OpenGameFileDialog();
        if (g_config.gamePath.empty()) {
            std::wcerr << L"[-] 用户取消选择" << std::endl;
            system("pause");
            return 1;
        }
        WritePrivateProfileStringW(L"Settings", L"GamePath", g_config.gamePath.c_str(), g_iniPath.c_str());
    }

    // 检查 DLL
    std::wstring dllPath = launcherDir + L"\\nvhelper.dll";
    if (!PathFileExistsW(dllPath.c_str())) {
        std::wcerr << L"[-] 找不到 nvhelper.dll 文件，请确保文件完整" << std::endl;
        system("pause");
        return 1;
    }

    std::wcout << L"[+] 游戏路径: " << g_config.gamePath << std::endl;
    std::wcout << L"[+] DLL路径: " << dllPath << std::endl;

    // 初始化共享内存
    if (!InitSharedMemory()) {
        system("pause");
        return 1;
    }
    UpdateSharedMemory();
    std::wcout << L"[+] 共享内存已初始化" << std::endl;

    // 初始化 UDP
    if (!InitUDP()) {
        CleanupSharedMemory();
        system("pause");
        return 1;
    }
    std::wcout << L"[+] UDP 客户端已初始化" << std::endl;

    // 创建游戏进程
    std::wstring workingDir = g_config.gamePath.substr(0, g_config.gamePath.find_last_of(L"\\/"));
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(
        g_config.gamePath.c_str(),
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
        std::wcerr << L"[-] 无法创建游戏进程: " << g_config.gamePath << std::endl;
        CleanupSharedMemory();
        CleanupUDP();
        system("pause");
        return 1;
    }

    std::wcout << L"[+] 游戏进程已创建 (PID: " << pi.dwProcessId << L")" << std::endl;

    // 注入 DLL
    if (!InjectDll(pi.hProcess, dllPath)) {
        std::wcerr << L"[-] 注入 DLL 失败" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CleanupSharedMemory();
        CleanupUDP();
        system("pause");
        return 1;
    }

    // 恢复游戏线程
    ResumeThread(pi.hThread);
    std::wcout << L"[+] 游戏已启动并成功注入" << std::endl;

    // 等待 DLL 初始化完成，然后发送 UDP 配置
    std::wcout << L"[+] 等待 DLL 初始化..." << std::endl;
    Sleep(3000);

    // 发送所有 UDP 配置
    SendAllUDPConfig();

    // 启动 BetterGI (如果配置了)
    bool betterGILaunched = false;
    if (!g_config.betterGIUri.empty()) {
        // 等待游戏窗口
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

        auto isRunning = [](HANDLE hProcess) -> bool {
            DWORD exitCode;
            return GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
        };

        std::wcout << L"[+] 等待游戏窗口..." << std::endl;
        while (isRunning(pi.hProcess)) {
            HWND mainWindow = getMainWindowHandle(pi.dwProcessId);
            if (mainWindow != nullptr) {
                std::wcout << L"[+] 正在启动 BetterGI: " << g_config.betterGIUri << std::endl;
                ShellExecuteW(nullptr, L"open", g_config.betterGIUri.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                betterGILaunched = true;
                break;
            }
            Sleep(10);
        }
    }

    // 启动 INI 文件监控线程
    std::thread monitorThread(FileMonitorThread);

    // 隐藏控制台窗口
    std::wcout << L"[+] 进入后台监控模式 (修改 INI 文件将自动应用配置)" << std::endl;
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 等待游戏退出
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 停止监控线程
    g_running = false;
    if (monitorThread.joinable()) {
        monitorThread.join();
    }

    // 关闭 BetterGI
    if (betterGILaunched && g_config.autoCloseBetterGI) {
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        std::wcout << L"[+] 游戏已关闭，正在关闭 BetterGI..." << std::endl;
        if (TerminateProcessByName(L"BetterGI.exe")) {
            std::wcout << L"[+] BetterGI 已关闭" << std::endl;
        }
        else {
            std::wcout << L"[*] BetterGI 未在运行或已关闭" << std::endl;
        }
    }

    // 清理
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CleanupUDP();
    CleanupSharedMemory();

    return 0;
}
