# Event log channels

Microsoft-Windows-Dhcp-Client/Admin
Microsoft-Windows-Dhcp-Client/Operational

Microsoft-Windows-Dhcpv6-Client/Operational
Microsoft-Windows-Dhcpv6-Client/Admin

Microsoft-Windows-DNS-Client/Operational

Microsoft-Windows-GroupPolicy/Operational

Microsoft-Windows-Hyper-V-Compute-Admin
Microsoft-Windows-Hyper-V-Compute-Operational

Microsoft-Windows-Hyper-V-Guest-Drivers/Admin
Microsoft-Windows-Hyper-V-Guest-Drivers/Operational

Microsoft-Windows-Hyper-V-Hypervisor-Admin
Microsoft-Windows-Hyper-V-Hypervisor-Operational

Microsoft-Windows-Hyper-V-StorageVSP-Admin

Microsoft-Windows-Hyper-V-VID-Admin

Microsoft-Windows-Hyper-V-VmSwitch-Operational

Microsoft-Windows-Hyper-V-Worker-Admin
Microsoft-Windows-Hyper-V-Worker-Operational+

Microsoft-Windows-PrintService/Admin
Microsoft-Windows-PrintService/Operational

Microsoft-Windows-Privacy-Auditing/Operational

Microsoft-Windows-PushNotification-Platform/Admin
Microsoft-Windows-PushNotification-Platform/Operational

Microsoft-Windows-RemoteApp and Desktop Connections/Admin
Microsoft-Windows-RemoteApp and Desktop Connections/Operational

Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin
Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational

Microsoft-Windows-Resource-Exhaustion-Detector/Operational

Microsoft-Windows-Resource-Exhaustion-Resolver/Operational

Microsoft-Windows-ServerManager-MultiMachine/Admin
Microsoft-Windows-ServerManager-MultiMachine/Operational

Microsoft-Windows-TaskScheduler/Maintenance
Microsoft-Windows-TaskScheduler/Operational

Microsoft-Windows-TerminalServices-RDPClient/Operational

Microsoft-Windows-TerminalServices-ClientUSBDevices/Admin
Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational

Microsoft-Windows-TerminalServices-LocalSessionManager/Admin
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

Microsoft-Windows-TerminalServices-PnPDevices/Admin
Microsoft-Windows-TerminalServices-PnPDevices/Operational

Microsoft-Windows-TerminalServices-Printers/Admin
Microsoft-Windows-TerminalServices-Printers/Operational

Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

Microsoft-Windows-TerminalServices-ServerUSBDevices/Admin
Microsoft-Windows-TerminalServices-ServerUSBDevices/Operational

Microsoft-Windows-Time-Service/Operational

Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational

Microsoft-Windows-UniversalTelemetryClient/Operational

Microsoft-Windows-Windows Defender/Operational
Microsoft-Windows-Windows Defender/WHC

Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity
Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose
Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics
Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose
Network Isolation Operational

Microsoft-Windows-WinRM/Operational

Microsoft-Windows-WindowsUpdateClient/Operational


# Powershell Commands

Get-WinEvent -ListLog *
Get-WinEvent -ListProvider *

Get-WinEvent -ListProvider "Microsoft-Windows-TerminalServices*" -ErrorAction SilentlyContinue | Select-Object *


```PowerShell
$EventProviders = Get-WinEvent -ListProvider "*" -ErrorAction SilentlyContinue

foreach($Provider in $EventProviders){

#    foreach($Event in $Provider.Events){
#        $Provider.Name     #System.String
#        $Event.Id          #System.Int64
#        $Event.LogLink     #System.Diagnostics.Eventing.Reader.EventLogLink    DisplayName, LogName
#        $Event.Level       #System.Diagnostics.Eventing.Reader.EventLevel      DisplayName, Name, Value
#        $Event.Opcode      #System.Diagnostics.Eventing.Reader.EventOpcode     DisplayName, Name, Value
#        $Event.Task        #System.Diagnostics.Eventing.Reader.EventTask       DisplayName EventGuid, Name, Value
#        $Event.Keywords    #System.Diagnostics.Eventing.Reader.EventKeyword    DisplayName, Name, Value
#        $Event.Description #System.String 
#    }

    foreach($Event in $Provider.Events){

        $OutputData = @{
            "ProviderName" = $Provider.Name;
            "EventId"      = $Event.Id;
            "LogLinkDisplayName" = $Event.LogLink.DisplayName;
            "LogLinkLogName" = $Event.LogLink.LogName;
            "LevelDisplayName" = $Event.Level.DisplayName;
            "LevelName" = $Event.Level.Name;
            "LevelValue" = $Event.Level.Value;
            "OpcodeDisplayName" = $Event.Opcode.DisplayName;
            "OpcodeName" = $Event.Opcode.Name;
            "OpcodeValue" = $Event.Opcode.Value;
            "TaskDisplayName" = $Event.Task.DisplayName;
            "TaskEventGuid" = $Event.Task.EventGuid;
            "TaskName" = $Event.Task.Name;
            "TaskValue" = $Event.Task.Value;
            "KeywordsDisplayName" = $Event.Keywords.DisplayName;
            "KeywordsName" = $Event.Keywords.Name;
            "KeywordsValue" = $Event.Keywords.Value;
            "Description" = $Event.Description
        }

        $OutputObject = [pscustomobject]$OutputData
        $OutputObject
    }
}
```
