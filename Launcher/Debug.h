#pragma once

#include <windows.h>

// 调试模式全局变量
extern bool g_debugMode;

// 调试输出函数
void DebugLog(const wchar_t* format, ...);
void DebugLogA(const char* format, ...);
