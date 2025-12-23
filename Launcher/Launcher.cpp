#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

#include "Debug.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// 常量定义
// ============================================================================
const int UDP_PORT = 12345;
const char* UDP_HOST = "127.0.0.1";

// ============================================================================
// Launcher.dll 函数类型定义
// ============================================================================
typedef void(__cdecl* UpdateConfigFunc)(
    const wchar_t* gamePath,
    int hideQuestBanner,
    int disableDamageText,
    int useTouchScreen,
    int disableEventCameraMove,
    int removeTeamProgress,
    int redirectCombineEntry,
    int resin106,
    int resin201,
    int resin107009,
    int resin107012,
    int resin220007
);

typedef int(__cdecl* LaunchGameAndInjectFunc)(
    const wchar_t* gamePath,
    const wchar_t* dllPath,
    const wchar_t* commandLineArgs,
    wchar_t* errorMessage,
    int errorMessageSize
);

typedef int(__cdecl* GetDefaultDllPathFunc)(
    wchar_t* dllPath,
    int dllPathSize
);

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

    // [Features] - 注入时通过 Launcher.dll 配置
    bool hideQuestBanner = false;
    bool disableDamageText = false;
    bool touchMode = false;
    bool disableEventCameraMove = false;
    bool removeTeamProgress = false;
    bool redirectCombine = false;
};

// ============================================================================
// 全局变量
// ============================================================================
LauncherConfig g_config;
LauncherConfig g_lastConfig;
std::wstring g_iniPath;
std::atomic<bool> g_running(true);
SOCKET g_udpSocket = INVALID_SOCKET;
DWORD g_gameProcessId = 0;

// Launcher.dll 函数指针
HMODULE g_hLauncherDll = nullptr;
UpdateConfigFunc g_pUpdateConfig = nullptr;
LaunchGameAndInjectFunc g_pLaunchGameAndInject = nullptr;
GetDefaultDllPathFunc g_pGetDefaultDllPath = nullptr;

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
// Launcher.dll 加载
// ============================================================================
bool LoadLauncherDll(const std::wstring& launcherDir) {
    std::wstring dllPath = launcherDir + L"\\Launcher.dll";

    DebugLog(L"正在加载 Launcher.dll: %s", dllPath.c_str());

    g_hLauncherDll = LoadLibraryW(dllPath.c_str());
    if (g_hLauncherDll == nullptr) {
        DWORD err = GetLastError();
        std::wcerr << L"[-] 无法加载 Launcher.dll (错误码: " << err << L")" << std::endl;
        return false;
    }

    g_pUpdateConfig = (UpdateConfigFunc)GetProcAddress(g_hLauncherDll, "UpdateConfig");
    g_pLaunchGameAndInject = (LaunchGameAndInjectFunc)GetProcAddress(g_hLauncherDll, "LaunchGameAndInject");
    g_pGetDefaultDllPath = (GetDefaultDllPathFunc)GetProcAddress(g_hLauncherDll, "GetDefaultDllPath");

    if (!g_pUpdateConfig || !g_pLaunchGameAndInject || !g_pGetDefaultDllPath) {
        std::wcerr << L"[-] 无法获取 Launcher.dll 函数地址" << std::endl;
        std::wcerr << L"    UpdateConfig: " << (g_pUpdateConfig ? L"OK" : L"FAIL") << std::endl;
        std::wcerr << L"    LaunchGameAndInject: " << (g_pLaunchGameAndInject ? L"OK" : L"FAIL") << std::endl;
        std::wcerr << L"    GetDefaultDllPath: " << (g_pGetDefaultDllPath ? L"OK" : L"FAIL") << std::endl;
        FreeLibrary(g_hLauncherDll);
        g_hLauncherDll = nullptr;
        return false;
    }

    DebugLog(L"Launcher.dll 加载成功");
    DebugLog(L"  UpdateConfig: 0x%p", g_pUpdateConfig);
    DebugLog(L"  LaunchGameAndInject: 0x%p", g_pLaunchGameAndInject);
    DebugLog(L"  GetDefaultDllPath: 0x%p", g_pGetDefaultDllPath);

    return true;
}

void UnloadLauncherDll() {
    if (g_hLauncherDll != nullptr) {
        FreeLibrary(g_hLauncherDll);
        g_hLauncherDll = nullptr;
    }
    g_pUpdateConfig = nullptr;
    g_pLaunchGameAndInject = nullptr;
    g_pGetDefaultDllPath = nullptr;
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

    // [Misc]
    g_debugMode = GetPrivateProfileIntW(L"Misc", L"EnableDebug", 0, g_iniPath.c_str()) != 0;

    // [Visual] - 运行时 UDP 配置
    g_config.enableFpsOverride = GetPrivateProfileIntW(L"Visual", L"EnableFpsOverride", 1, g_iniPath.c_str()) != 0;
    g_config.selectedFps = GetPrivateProfileIntW(L"Visual", L"SelectedFps", 60, g_iniPath.c_str());
    g_config.enableFovOverride = GetPrivateProfileIntW(L"Visual", L"EnableFovOverride", 0, g_iniPath.c_str()) != 0;

    wchar_t fovStr[32] = { 0 };
    GetPrivateProfileStringW(L"Visual", L"FovValue", L"45.0", fovStr, 32, g_iniPath.c_str());
    g_config.fovValue = static_cast<float>(_wtof(fovStr));

    g_config.enableFogOverride = GetPrivateProfileIntW(L"Visual", L"EnableFogOverride", 0, g_iniPath.c_str()) != 0;
    g_config.enablePerspectiveOverride = GetPrivateProfileIntW(L"Visual", L"EnablePerspectiveOverride", 0, g_iniPath.c_str()) != 0;

    // [Features] - 启动时通过 Launcher.dll 配置
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
// 游戏进程监控
// ============================================================================
bool IsProcessRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == nullptr) return false;

    DWORD exitCode;
    BOOL result = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);

    return result && exitCode == STILL_ACTIVE;
}

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

// ============================================================================
// 主函数
// ============================================================================
int wmain() {
    std::locale::global(std::locale("zh_CN.UTF-8"));
    std::wcout.imbue(std::locale("zh_CN.UTF-8"));

    std::wcout << L"========================================" << std::endl;
    std::wcout << L"  原神启动器 (Launcher.dll 版本)" << std::endl;
    std::wcout << L"========================================" << std::endl;

    // 获取路径
    wchar_t launcherExePath[MAX_PATH];
    GetModuleFileNameW(nullptr, launcherExePath, MAX_PATH);
    std::wstring launcherPath = launcherExePath;
    std::wstring launcherDir = launcherPath.substr(0, launcherPath.find_last_of(L"\\/"));
    g_iniPath = launcherPath.substr(0, launcherPath.find_last_of(L'.')) + L".ini";

    DebugLog(L"启动器路径: %s", launcherPath.c_str());
    DebugLog(L"启动器目录: %s", launcherDir.c_str());
    DebugLog(L"配置文件路径: %s", g_iniPath.c_str());

    // 检查 INI 文件是否存在，不存在则创建默认配置
    if (GetFileAttributesW(g_iniPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[+] 创建默认配置文件..." << std::endl;
        SaveDefaultConfig();
    }

    // 加载配置
    LoadConfig();
    g_lastConfig = g_config;

    if (g_debugMode) {
        std::wcout << L"[+] 调试模式已启用" << std::endl;
    }

    // 加载 Launcher.dll
    if (!LoadLauncherDll(launcherDir)) {
        system("pause");
        return 1;
    }
    std::wcout << L"[+] Launcher.dll 已加载" << std::endl;

    // 检查游戏路径
    if (g_config.gamePath.empty() || !PathFileExistsW(g_config.gamePath.c_str())) {
        std::wcout << L"[+] 请选择游戏文件..." << std::endl;
        g_config.gamePath = OpenGameFileDialog();
        if (g_config.gamePath.empty()) {
            std::wcerr << L"[-] 用户取消选择" << std::endl;
            UnloadLauncherDll();
            system("pause");
            return 1;
        }
        WritePrivateProfileStringW(L"Settings", L"GamePath", g_config.gamePath.c_str(), g_iniPath.c_str());
    }

    std::wcout << L"[+] 游戏路径: " << g_config.gamePath << std::endl;

    // 获取默认 DLL 路径
    wchar_t dllPathBuffer[MAX_PATH] = { 0 };
    int dllPathResult = g_pGetDefaultDllPath(dllPathBuffer, MAX_PATH);
    std::wstring dllPath = dllPathBuffer;

    if (dllPathResult != 0 || dllPath.empty()) {
        std::wcerr << L"[-] 无法获取注入 DLL 路径" << std::endl;
        UnloadLauncherDll();
        system("pause");
        return 1;
    }

    std::wcout << L"[+] 注入 DLL: " << dllPath << std::endl;

    // 初始化 UDP
    if (!InitUDP()) {
        UnloadLauncherDll();
        system("pause");
        return 1;
    }
    std::wcout << L"[+] UDP 客户端已初始化" << std::endl;

    // 调用 UpdateConfig 更新共享内存配置
    std::wcout << L"[+] 正在更新配置..." << std::endl;
    DebugLog(L"Features 配置:");
    DebugLog(L"  HideQuestBanner: %d", g_config.hideQuestBanner ? 1 : 0);
    DebugLog(L"  DisableDamageText: %d", g_config.disableDamageText ? 1 : 0);
    DebugLog(L"  TouchMode: %d", g_config.touchMode ? 1 : 0);
    DebugLog(L"  DisableEventCameraMove: %d", g_config.disableEventCameraMove ? 1 : 0);
    DebugLog(L"  RemoveTeamProgress: %d", g_config.removeTeamProgress ? 1 : 0);
    DebugLog(L"  RedirectCombine: %d", g_config.redirectCombine ? 1 : 0);

    g_pUpdateConfig(
        g_config.gamePath.c_str(),
        g_config.hideQuestBanner ? 1 : 0,
        g_config.disableDamageText ? 1 : 0,
        g_config.touchMode ? 1 : 0,
        g_config.disableEventCameraMove ? 1 : 0,
        g_config.removeTeamProgress ? 1 : 0,
        g_config.redirectCombine ? 1 : 0,
        0, 0, 0, 0, 0  // resin 参数暂时都设为 0
    );
    std::wcout << L"[+] 配置已同步到共享内存" << std::endl;

    // 调用 LaunchGameAndInject 启动游戏并注入
    std::wcout << L"[+] 正在启动游戏并注入..." << std::endl;
    wchar_t errorBuffer[1024] = { 0 };
    int launchResult = g_pLaunchGameAndInject(
        g_config.gamePath.c_str(),
        dllPath.c_str(),
        L"",  // 命令行参数
        errorBuffer,
        1024
    );

    if (launchResult != 0) {
        std::wcerr << L"[-] 启动游戏失败 (错误码: " << launchResult << L")" << std::endl;
        if (wcslen(errorBuffer) > 0) {
            std::wcerr << L"    错误信息: " << errorBuffer << std::endl;
        }
        CleanupUDP();
        UnloadLauncherDll();
        system("pause");
        return 1;
    }

    // 成功时 errorBuffer 包含进程 ID
    g_gameProcessId = _wtoi(errorBuffer);
    std::wcout << L"[+] 游戏已启动并成功注入 (PID: " << g_gameProcessId << L")" << std::endl;

    // 等待 DLL 初始化完成，然后发送 UDP 配置
    std::wcout << L"[+] 等待 DLL 初始化..." << std::endl;
    Sleep(3000);

    // 发送所有 UDP 配置
    SendAllUDPConfig();

    // 启动 BetterGI (如果配置了)
    bool betterGILaunched = false;
    if (!g_config.betterGIUri.empty() && g_gameProcessId != 0) {
        std::wcout << L"[+] 等待游戏窗口..." << std::endl;
        while (IsProcessRunning(g_gameProcessId)) {
            HWND mainWindow = GetMainWindowHandle(g_gameProcessId);
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

    // 调试模式下不隐藏控制台窗口
    if (!g_debugMode) {
        std::wcout << L"[+] 进入后台监控模式 (修改 INI 文件将自动应用配置)" << std::endl;
        ShowWindow(GetConsoleWindow(), SW_HIDE);
    }
    else {
        std::wcout << L"[+] 调试模式: 控制台窗口保持可见" << std::endl;
        std::wcout << L"[+] 等待游戏退出..." << std::endl;
    }

    // 等待游戏退出
    if (g_gameProcessId != 0) {
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, g_gameProcessId);
        if (hProcess != nullptr) {
            WaitForSingleObject(hProcess, INFINITE);
            CloseHandle(hProcess);
        }
    }

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
    CleanupUDP();
    UnloadLauncherDll();

    return 0;
}
