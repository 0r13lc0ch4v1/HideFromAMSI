# HideFromAMSI

HideFromAMSI is a simple C# example of how to Execute a PowerShell script from C# and Bypass AMSI using [CyberArk's method to bypass AMSI].

This code doesn't open a PowerShell subprocess, but there are method that do, if you do open a PowerShell process, 
use the HookAmsiScanBuffer function before you decrypt the script. Moreover, in this code I used [Mimikatz], 
but other scripts may need different code.

From what I've seen, it is better to open PowerShell (from C# using [CreateOutOfProcessRunspace]) as a subprocess 
and override that PowerShell's AMSI using HookAmsiScanBuffer (passing the [PowerShellProcessInstance]'s handle to the hooking function).

[CyberArk's method to bypass AMSI]: <https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/>
[Mimikatz]: <https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz>
[CreateOutOfProcessRunspace]: <https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspacefactory.createoutofprocessrunspace?view=powershellsdk-1.1.0#System_Management_Automation_Runspaces_RunspaceFactory_CreateOutOfProcessRunspace_System_Management_Automation_Runspaces_TypeTable_System_Management_Automation_Runspaces_PowerShellProcessInstance_>
[PowerShellProcessInstance]: <https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.powershellprocessinstance?view=powershellsdk-1.1.0>

For educational purposes only!
