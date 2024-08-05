#include <iostream>
#include <fstream>
#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <string>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

std::ofstream log_file;

std::string wstring_to_string(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
    return str;
}

std::wstring get_executable_path() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH)) {
        return std::wstring(path);
    }
    return L"";
}

void set_console_color(WORD color) {
    HANDLE h_console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h_console, color);
}

void reset_console_color() {
    set_console_color(FOREGROUND_INTENSITY);
}

void log_header(const std::wstring& header) {
    const std::wstring border = L"===================================================";

    set_console_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    size_t border_length = border.size();
    size_t header_length = header.size();
    size_t padding_length = border_length - header_length - 4;

    if (padding_length < 0) padding_length = 0;

    size_t left_padding = padding_length / 2;
    size_t right_padding = padding_length - left_padding;

    std::wcout << border << std::endl;
    std::wcout << L"==" << std::wstring(left_padding, L' ') << header << std::wstring(right_padding, L' ') << L"==" << std::endl;
    std::wcout << border << std::endl;

    reset_console_color();
}

void log_message(const std::wstring& message, bool error = false) {
    set_console_color(error ? FOREGROUND_RED : FOREGROUND_INTENSITY);
    std::wcout << message << std::endl;
    reset_console_color();

    std::wofstream log_file(get_executable_path().substr(0, get_executable_path().find_last_of(L"\\") + 1) + L"program_log.txt", std::ios::app);
    if (log_file.is_open()) {
        log_file << message << std::endl;
        log_file.close();
    }
    else {
        set_console_color(FOREGROUND_RED);
        std::wcerr << L"Log file is not open. Cannot write message: " << message << std::endl;
        reset_console_color();
    }
}

void set_registry_value(HKEY h_key, const std::wstring& sub_key, const std::wstring& value_name, DWORD value) {
    HKEY key;
    LONG result = RegCreateKeyEx(h_key, sub_key.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(key, value_name.c_str(), 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
        if (result != ERROR_SUCCESS) {
            log_message(L"Error setting registry value for " + sub_key + L" - " + value_name + L": " + std::to_wstring(result), true);
        }
        else {
            log_message(L"Set registry value " + value_name + L" [" + sub_key + L"]", false);
        }
        RegCloseKey(key);
    }
    else {
        log_message(L"Error opening or creating registry key " + sub_key + L": " + std::to_wstring(result), true);
    }
}

void stop_and_disable_service(const std::wstring& service_name) {
    SC_HANDLE scm_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm_handle) {
        log_message(L"Error opening Service Control Manager: " + std::to_wstring(GetLastError()), true);
        return;
    }

    SC_HANDLE service_handle = OpenService(scm_handle, service_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (!service_handle) {
        log_message(L"Error opening service " + service_name + L": " + std::to_wstring(GetLastError()), true);
        CloseServiceHandle(scm_handle);
        return;
    }

    SERVICE_STATUS_PROCESS service_status;
    DWORD bytes_needed;
    if (QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, (LPBYTE)&service_status, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)) {
        if (service_status.dwCurrentState == SERVICE_RUNNING) {
            log_message(L"Stopping " + service_name + L"...", false);
            if (ControlService(service_handle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&service_status)) {
                Sleep(1000);
                while (QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, (LPBYTE)&service_status, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed) && service_status.dwCurrentState != SERVICE_STOPPED) {
                    Sleep(1000);
                }
                log_message(service_name + L" stopped.", false);
            }
            else {
                log_message(L"Error stopping service " + service_name + L": " + std::to_wstring(GetLastError()), true);
            }
        }
    }
    else {
        log_message(L"Error querying service status for " + service_name + L": " + std::to_wstring(GetLastError()), true);
    }

    if (ChangeServiceConfig(service_handle, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
        log_message(L"Disabled service " + service_name, false);
    }
    else {
        log_message(L"Error disabling service " + service_name + L": " + std::to_wstring(GetLastError()), true);
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

    if (!ChangeServiceConfig2(service_handle, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)) {
        log_message(L"Error setting failure actions for " + service_name + L": " + std::to_wstring(GetLastError()), true);
    }

    CloseServiceHandle(service_handle);
    CloseServiceHandle(scm_handle);
}

void disable_windows_defender() {
    log_header(L"Disabling Windows Defender and Related Services");

    stop_and_disable_service(L"WdNisSvc");
    stop_and_disable_service(L"WinDefend");
    stop_and_disable_service(L"SecurityHealthService");
    stop_and_disable_service(L"Sense");
    stop_and_disable_service(L"WdNisDrv");
    stop_and_disable_service(L"WDSS");

    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 1);
    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", 1);
    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableScanOnRealtimeEnable", 1);
    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\FeatureControl", L"DisableAntiExploit", 1);
    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\FeatureControl", L"DisableAntiMalware", 1);
}

void disable_windows_update() {
    log_header(L"Disabling Windows Update and Related Services");

    stop_and_disable_service(L"wuauserv");
    stop_and_disable_service(L"bits");
    stop_and_disable_service(L"dosvc");

    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"NoAutoUpdate", 1);
    set_registry_value(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"DisableWindowsUpdateAccess", 1);
}

void create_scheduled_task() {
    log_header(L"Creating Scheduled Task to Enforce Settings");
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        log_message(L"CoInitializeEx failed: " + std::to_wstring(hr), true);
        return;
    }

    ITaskService* p_service = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&p_service);
    if (FAILED(hr)) {
        log_message(L"CoCreateInstance failed: " + std::to_wstring(hr), true);
        CoUninitialize();
        return;
    }

    hr = p_service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        log_message(L"ITaskService::Connect failed: " + std::to_wstring(hr), true);
        p_service->Release();
        CoUninitialize();
        return;
    }

    ITaskFolder* p_root_folder = NULL;
    hr = p_service->GetFolder(_bstr_t(L"\\"), &p_root_folder);
    if (FAILED(hr)) {
        log_message(L"Cannot get Root Folder pointer: " + std::to_wstring(hr), true);
        p_service->Release();
        CoUninitialize();
        return;
    }

    hr = p_root_folder->DeleteTask(_bstr_t(L"EnforceDisableDefenderAndUpdate"), 0);

    ITaskDefinition* p_task = NULL;
    hr = p_service->NewTask(0, &p_task);
    p_service->Release();
    if (FAILED(hr)) {
        log_message(L"Failed to create a task definition: " + std::to_wstring(hr), true);
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    IRegistrationInfo* p_reg_info = NULL;
    hr = p_task->get_RegistrationInfo(&p_reg_info);
    if (SUCCEEDED(hr)) {
        p_reg_info->put_Author(_bstr_t(L"Your Name"));
        p_reg_info->Release();
    }

    ITriggerCollection* p_trigger_collection = NULL;
    hr = p_task->get_Triggers(&p_trigger_collection);
    if (FAILED(hr)) {
        log_message(L"Cannot get trigger collection: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    ITrigger* p_trigger = NULL;
    hr = p_trigger_collection->Create(TASK_TRIGGER_LOGON, &p_trigger);
    p_trigger_collection->Release();
    if (FAILED(hr)) {
        log_message(L"Cannot create trigger: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    ILogonTrigger* p_logon_trigger = NULL;
    hr = p_trigger->QueryInterface(IID_ILogonTrigger, (void**)&p_logon_trigger);
    p_trigger->Release();
    if (FAILED(hr)) {
        log_message(L"QueryInterface call failed for ILogonTrigger: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    p_logon_trigger->put_Id(_bstr_t(L"Trigger1"));
    p_logon_trigger->put_UserId(_bstr_t(L"S-1-5-18"));
    p_logon_trigger->Release();

    IActionCollection* p_action_collection = NULL;
    hr = p_task->get_Actions(&p_action_collection);
    if (FAILED(hr)) {
        log_message(L"Cannot get Task collection: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    IAction* p_action = NULL;
    hr = p_action_collection->Create(TASK_ACTION_EXEC, &p_action);
    p_action_collection->Release();
    if (FAILED(hr)) {
        log_message(L"Cannot create the action: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    IExecAction* p_exec_action = NULL;
    hr = p_action->QueryInterface(IID_IExecAction, (void**)&p_exec_action);
    p_action->Release();
    if (FAILED(hr)) {
        log_message(L"QueryInterface call failed for IExecAction: " + std::to_wstring(hr), true);
        p_task->Release();
        p_root_folder->Release();
        CoUninitialize();
        return;
    }

    p_exec_action->put_Path(_bstr_t(get_executable_path().c_str()));
    p_exec_action->Release();

    IRegisteredTask* p_registered_task = NULL;
    hr = p_root_folder->RegisterTaskDefinition(_bstr_t(L"EnforceDisableDefenderAndUpdate"), p_task, TASK_CREATE_OR_UPDATE, _variant_t(L"S-1-5-18"), _variant_t(), TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""), &p_registered_task);
    if (FAILED(hr)) {
        log_message(L"Error saving the Task : " + std::to_wstring(hr), true);
    }
    else {
        log_message(L"Success! Task successfully registered.", false);
    }

    p_registered_task->Release();
    p_root_folder->Release();
    p_task->Release();
    CoUninitialize();
}

int main() {
    log_file.open(get_executable_path().substr(0, get_executable_path().find_last_of(L"\\") + 1) + L"program_log.txt", std::ios::app);
    disable_windows_defender();
    disable_windows_update();
    create_scheduled_task();
    log_message(L"Windows Defender and Windows Updates should be disabled. Please restart your computer to apply changes.", false);
    log_file.close();
    return 0;
}
