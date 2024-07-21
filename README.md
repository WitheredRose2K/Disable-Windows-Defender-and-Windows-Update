## Disable Windows Defender and Windows Update
A console application for Windows that disables Windows Defender and Windows Update services, and sets up a scheduled task to enforce these settings.

## Features
Disables Windows Defender's real-time protection, anti-spyware, anti-malware, and related features.
Disables Windows Update and related services.
Creates a scheduled task to enforce these settings.
Requires administrative privileges to run.
## Requirements
Windows 10 or later
Administrative privileges
## Installation
Clone the repository:

```bash
git clone https://github.com/WitheredRose2K/Disable-Windows-Defender-and-Windows-Update.git
```
Navigate to the project directory:

```bash
cd Disable-Windows-Defender-and-Windows-Update
```
Build the project using Visual Studio or another compatible build system.

## Usage
Run the application as an administrator. The program will prompt you to restart with administrative privileges if not already elevated.

The application will disable Windows Defender and Windows Update services, and create a scheduled task to reapply these settings if needed.

The status of operations will be displayed in the console, and a log file named program_log.txt will be created in the same directory.

Follow the on-screen instructions to complete the process.

## Example terminal output
```
===================================================
==          Disabling Windows Defender           ==
===================================================
Set registry value DisableRealtimeMonitoring [SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
Set registry value DisableAntiSpyware [SOFTWARE\Policies\Microsoft\Windows Defender]
Set registry value DisableScanOnRealtimeEnable [SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
Set registry value DisableAntiExploit [SOFTWARE\Policies\Microsoft\Windows Defender\FeatureControl]
Set registry value DisableAntiMalware [SOFTWARE\Policies\Microsoft\Windows Defender\FeatureControl]
===================================================
== Disabling Windows Update and Related Services ==
===================================================
Disabled service wuauserv
Disabled service bits
Error disabling service dosvc: 5
Set registry value NoAutoUpdate [SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
Set registry value DisableOSUpgrade [SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
===================================================
==  Creating Scheduled Task to Enforce Settings  ==
===================================================
Failed to register scheduled task: -2147216615
===================================================
== Completed successfully, press Enter to exit.  ==
===================================================
```
## Notes
Security Warning: Disabling Windows Defender and Windows Update can expose your system to security risks. Ensure you understand the implications before proceeding.
The application may require a system reboot to fully apply changes.
If the application fails to start with administrative privileges, you will be prompted to restart it manually with elevated permissions.
## License
This project is licensed under the MIT License
