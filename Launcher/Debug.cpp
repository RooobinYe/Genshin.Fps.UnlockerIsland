#include "Debug.h"
#include <iostream>
#include <cstdarg>

// 调试模式全局变量
bool g_debugMode = false;

void DebugLog(const wchar_t* format, ...) {
    if (!g_debugMode) return;

    va_list args;
    va_start(args, format);
    wchar_t buffer[1024];
    vswprintf_s(buffer, format, args);
    va_end(args);

    std::wcout << L"[DEBUG] " << buffer << std::endl;
}

void DebugLogA(const char* format, ...) {
    if (!g_debugMode) return;

    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsprintf_s(buffer, format, args);
    va_end(args);

    std::cout << "[DEBUG] " << buffer << std::endl;
}
