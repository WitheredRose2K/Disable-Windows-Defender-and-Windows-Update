#include <iostream>
#include <fstream>
#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <string>
#include <locale>
#include <sstream>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

std::ofstream logFile;

std::string WStringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
    return str;
}

std::wstring GetExecutablePath() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH)) {
        return std::wstring(path);
    }
    return L"";
}

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void ResetConsoleColor() {
    SetConsoleColor(FOREGROUND_INTENSITY);
}

void LogHeader(const std::wstring& header) {
    const std::wstring border = L"===================================================";

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    size_t borderLength = border.size();
    size_t headerLength = header.size();
    size_t paddingLength = borderLength - headerLength - 4;

    if (paddingLength < 0) paddingLength = 0;

    size_t leftPadding = paddingLength / 2;
    size_t rightPadding = paddingLength - leftPadding;

    std::wcout << border << std::endl;

    std::wcout << L"==" << std::wstring(leftPadding, L' ') << header << std::wstring(rightPadding, L' ') << L"==" << std::endl;

    std::wcout << border << std::endl;

    ResetConsoleColor();
}

void LogMessage(const std::wstring& message, bool error = false) {
    SetConsoleColor(error ? FOREGROUND_RED : FOREGROUND_INTENSITY);
    std::wcout << message << std::endl;
    ResetConsoleColor();

    std::wofstream logFile(GetExecutablePath().substr(0, GetExecutablePath().find_last_of(L"\\") + 1) + L"program_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::wcerr << L"Log file is not open. Cannot write message: " << message << std::endl;
        ResetConsoleColor();
    }
}

void SetRegistryValue(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, DWORD value) {
    HKEY key;
    LONG result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(key, valueName.c_str(), 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
        if (result != ERROR_SUCCESS) {
            LogMessage(L"Error setting registry value for " + subKey + L" - " + valueName + L": " + std::to_wstring(result), true);
        }
        else {
            LogMessage(L"Set registry value " + valueName + L" [" + subKey + L"]", false);
        }
        RegCloseKey(key);
    }
    else {
        LogMessage(L"Error opening or creating registry key " + subKey + L": " + std::to_wstring(result), true);
    }
}

void StopAndDisableService(const std::wstring& serviceName) {
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scmHandle) {
        LogMessage(L"Error opening Service Control Manager: " + std::to_wstring(GetLastError()), true);
        return;
    }

    SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (!serviceHandle) {
        LogMessage(L"Error opening service " + serviceName + L": " + std::to_wstring(GetLastError()), true);
        CloseServiceHandle(scmHandle);
        return;
    }

    SERVICE_STATUS_PROCESS serviceStatus;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
            LogMessage(L"Stopping " + serviceName + L"...", false);
            if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&serviceStatus)) {
                Sleep(1000);
                while (QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded) && serviceStatus.dwCurrentState != SERVICE_STOPPED) {
                    Sleep(1000);
                }
                LogMessage(serviceName + L" stopped.", false);
            }
            else {
                LogMessage(L"Error stopping service " + serviceName + L": " + std::to_wstring(GetLastError()), true);
            }
        }
    }
    else {
        LogMessage(L"Error querying service status for " + serviceName + L": " + std::to_wstring(GetLastError()), true);
    }

    if (ChangeServiceConfig(serviceHandle, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        LogMessage(L"Disabled service " + serviceName, false);
    }
    else {
        LogMessage(L"Error disabling service " + serviceName + L": " + std::to_wstring(GetLastError()), true);
    }

    SERVICE_FAILURE_ACTIONS sfa;
    SC_ACTION actions[3];

    actions[0].Type = SC_ACTION_NONE;
    actions[0].Delay = 0;
    actions[1].Type = SC_ACTION_NONE;
    actions[1].Delay = 0;
    actions[2].Type = SC_ACTION_NONE;
    actions[2].Delay = 0;

    sfa.dwResetPeriod = INFINITE;
    sfa.lpRebootMsg = NULL;
    sfa.lpCommand = NULL;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;

    if (!ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)) {
        LogMessage(L"Error setting failure actions for " + serviceName + L": " + std::to_wstring(GetLastError()), true);
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
}

void DisableWindowsDefender() {
    LogHeader(L"Disabling Windows Defender and Related Services");

    StopAndDisableService(L"WdNisSvc");
    StopAndDisableService(L"WinDefend");
    StopAndDisableService(L"SecurityHealthService");
    StopAndDisableService(L"Sense");
    StopAndDisableService(L"WdNisDrv");
    StopAndDisableService(L"WDSS");

    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 1);
    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", 1);
    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableScanOnRealtimeEnable", 1);
    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\FeatureControl", L"DisableAntiExploit", 1);
    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\FeatureControl", L"DisableAntiMalware", 1);
}

void DisableWindowsUpdate() {
    LogHeader(L"Disabling Windows Update and Related Services");

    StopAndDisableService(L"wuauserv");
    StopAndDisableService(L"bits");
    StopAndDisableService(L"dosvc");

    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"NoAutoUpdate", 1);
    SetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"DisableWindowsUpdateAccess", 1);
}

void CreateScheduledTask() {
    LogHeader(L"Creating Scheduled Task to Enforce Settings");
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        LogMessage(L"CoInitializeEx failed: " + std::to_wstring(hr), true);
        return;
    }

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        LogMessage(L"Failed to create an instance of ITaskService: " + std::to_wstring(hr), true);
        CoUninitialize();
        return;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        LogMessage(L"Failed to connect to task scheduler: " + std::to_wstring(hr), true);
        pService->Release();
        CoUninitialize();
        return;
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        LogMessage(L"Failed to get the root folder: " + std::to_wstring(hr), true);
        pService->Release();
        CoUninitialize();
        return;
    }

    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        LogMessage(L"Failed to create new task definition: " + std::to_wstring(hr), true);
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return;
    }

    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr)) {
        LogMessage(L"Failed to get registration info: " + std::to_wstring(hr), true);
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return;
    }

    hr = pRegInfo->put_Author(_bstr_t(L"Disable Windows Defender and Windows Update"));
    pRegInfo->Release();
    if (FAILED(hr)) {
        LogMessage(L"Failed to set task author: " + std::to_wstring(hr), true);
    }

    ITaskSettings* pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (FAILED(hr)) {
        LogMessage(L"Cannot get settings pointer: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
    pSettings->Release();
    if (FAILED(hr)) {
        LogMessage(L"Cannot put settings: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (FAILED(hr)) {
        LogMessage(L"Cannot get trigger collection: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    ITrigger* pTrigger = NULL;
    hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
    pTriggerCollection->Release();
    if (FAILED(hr)) {
        LogMessage(L"Cannot create trigger: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    IDailyTrigger* pDailyTrigger = NULL;
    hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger);
    pTrigger->Release();
    if (FAILED(hr)) {
        LogMessage(L"Cannot query for daily trigger: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    hr = pDailyTrigger->put_DaysInterval(1);
    pDailyTrigger->Release();
    if (FAILED(hr)) {
        LogMessage(L"Cannot set daily trigger interval: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    IActionCollection* pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (FAILED(hr)) {
        LogMessage(L"Cannot get action collection pointer: " + std::to_wstring(hr));
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    IAction* pAction = NULL;
    hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pActionCollection->Release();
    if (FAILED(hr)) {
        LogMessage(L"Cannot create action: " + std::to_wstring(hr), true);
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    IExecAction* pExecAction = NULL;
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    pAction->Release();
    if (FAILED(hr)) {
        LogMessage(L"QueryInterface call failed for IExecAction: " + std::to_wstring(hr), true);
        pTask->Release();
        pRootFolder->Release();
        CoUninitialize();
        return;
    }

    std::wstring exePath = GetExecutablePath();

    hr = pExecAction->put_Path(_bstr_t(exePath.c_str()));
    if (FAILED(hr)) {
        LogMessage(L"Cannot put executable path: " + std::to_wstring(hr)), true;
        pExecAction->Release();
        pTask->Release();
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return;
    }

    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(L"DisableDefenderAndUpdate"),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(L"SYSTEM"),
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask
    );

    if (FAILED(hr)) {
        LogMessage(L"Failed to register scheduled task: " + std::to_wstring(hr), true);
    }
    else {
        LogMessage(L"Scheduled task created successfully.", false);
    }

    if (pRegisteredTask) pRegisteredTask->Release();
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    CoUninitialize();
}
void RestartComputer() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
            if (ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_FLAG_PLANNED)) {
                LogMessage(L"Restarting computer...", false);
            }
            else {
                LogMessage(L"Failed to initiate computer restart: " + std::to_wstring(GetLastError()), true);
            }
        }
        else {
            LogMessage(L"Failed to adjust token privileges: " + std::to_wstring(GetLastError()), true);
        }
        CloseHandle(hToken);
    }
    else {
        LogMessage(L"Failed to open process token: " + std::to_wstring(GetLastError()), true);
    }
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {

        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }

        FreeSid(administratorsGroup);
    }

    return isAdmin == TRUE;
}

void RestartAsAdmin(const std::wstring& executablePath) {
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = executablePath.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        MessageBoxW(NULL, L"Failed to restart the program with administrative privileges.", L"Restart Failed", MB_ICONERROR | MB_OK);
        ExitProcess(0);
    }

    ExitProcess(0);
}

int main() {
    if (!IsRunningAsAdmin()) {
        std::wstring executablePath = GetExecutablePath();

        int msgBoxResult = MessageBoxW(
            NULL,
            L"This program requires administrative privileges to run correctly. Would you like to restart it with administrative privileges?",
            L"Administrative Privileges Required",
            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2
        );

        if (msgBoxResult == IDYES) {
            if (!executablePath.empty()) {
                RestartAsAdmin(executablePath);
            }
            else {
                MessageBoxW(
                    NULL,
                    L"Unable to determine the executable path. Please restart the program manually as an administrator.",
                    L"Path Error",
                    MB_ICONERROR | MB_OK
                );
                return 1;
            }
        }
        else {
            MessageBoxW(
                NULL,
                L"The program cannot continue without administrative privileges. Please restart it as an administrator.",
                L"Action Required",
                MB_ICONERROR | MB_OK
            );
        }

        return 1;
    }

    logFile.open(GetExecutablePath().substr(0, GetExecutablePath().find_last_of(L"\\") + 1) + L"program_log.txt", std::ios::out | std::ios::trunc);
    if (!logFile.is_open()) {
        LogMessage(L"Failed to open log file. Check permissions and path.", true);
        return 1;
    }

    bool hit_catch = false;

    try {
        DisableWindowsDefender();
        DisableWindowsUpdate();
        LogMessage(L"Creating scheduled tasks...");
        CreateScheduledTask();

        LogHeader(L"Completed, please choose restart preference");
        int restartMsgBoxID = MessageBoxW(
            NULL,
            L"Your computer needs to restart to apply changes. Do you want to restart now?",
            L"Restart Required",
            MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2
        );

        if (restartMsgBoxID == IDYES) {
            LogMessage(L"Restarting computer...");
            RestartComputer();
        }
        else {
            LogMessage(L"User chose to restart later.");
            logFile.close();
            return 0;
        }
    }
    catch (const std::exception& e) {
        LogMessage(L"Standard exception caught: " + std::wstring(e.what(), e.what() + strlen(e.what())), true);
        hit_catch = true;
    }
    catch (...) {
        LogMessage(L"Unknown exception caught.", true);
        hit_catch = true;
    }

    if (hit_catch) {
        LogMessage(L"Failed, press Enter to exit.", true);
    }

    std::cin.ignore();
    logFile.close();
    return 0;
}
