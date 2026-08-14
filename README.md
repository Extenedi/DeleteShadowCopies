# VSS Shadow Copy Deletion Tool

## ⚠️ CRITICAL WARNING: RANSOMWARE COMPONENT

This is a **Shadow Copy deletion tool** commonly used in ransomware attacks to prevent victim recovery. This code should **NEVER** be executed outside of isolated research environments and is documented here for defensive security purposes only.

---

## Overview

A C++ program that deletes Windows Shadow Copies (Volume Shadow Service snapshots) without using traditional command-line tools like `wmic` or `vssadmin`. This tool directly interfaces with the Windows VSS API to enumerate and delete all shadow copies on the system.

**Author**: ORCA (@ORCx41)  
**Date**: 10/31/2022  
**Tested On**: Windows 10 v10.0.19044 x64

---

## Technical Details

## Demo (Creating):
![poc1](https://user-images.githubusercontent.com/111295429/198935990-45b552f9-bce7-44ae-8a91-37f50d81c760.png)

<br>

## Demo (Deleting):
![poc2](https://user-images.githubusercontent.com/111295429/198935994-48041574-4e6b-4a99-b1e0-a6bdfc552a80.png)

### Core Functionality

The program performs the following operations:

1. **COM Initialization**
   - Initializes Component Object Model (COM)
   - Sets up security context with `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`
   - Enables dynamic cloaking for security

2. **VSS Component Creation**
   - Creates `IVssBackupComponents` interface
   - Initializes VSS backup infrastructure
   - Sets context to `VSS_CTX_ALL` (all shadow copy types)

3. **Shadow Copy Enumeration**
   - Queries for all existing shadow copies
   - Uses `IVssEnumObject` to iterate through snapshots
   - Retrieves metadata: SnapshotID, OriginalVolume, ProviderID

4. **Shadow Copy Deletion**
   - Deletes each snapshot individually
   - Uses `DeleteSnapshots()` with `VSS_OBJECT_SNAPSHOT` flag
   - Continues until no more shadow copies exist

### Key Windows APIs Used

| API Function | Purpose |
|--------------|---------|
| `CoInitialize()` | Initialize COM library |
| `CoInitializeSecurity()` | Set COM security blanket |
| `CreateVssBackupComponents()` | Create VSS backup interface |
| `InitializeForBackup()` | Prepare VSS for backup operations |
| `SetContext()` | Define VSS context scope |
| `SetBackupState()` | Configure backup state |
| `Query()` | Enumerate shadow copies |
| `DeleteSnapshots()` | Remove shadow copy by ID |
| `VssFreeSnapshotPropertiesInternal()` | Free snapshot property memory |

### Dependencies

```cpp
#include <vss.h>        // VSS core definitions
#include <vswriter.h>   // VSS writer interface
#include <vsbackup.h>   // VSS backup interface
#include <vsmgmt.h>     // VSS management
#include <atlcomcli.h>  // ATL COM smart pointers

#pragma comment (lib, "VssApi.lib")
#pragma comment (lib, "ResUtils.lib")
```

---

## How It Works

### Execution Flow

```
1. Initialize COM & Security
   ↓
2. Create VSS Backup Components
   ↓
3. Set VSS Context (VSS_CTX_ALL)
   ↓
4. Set Backup State (Full Backup)
   ↓
5. Query All Shadow Copies (GUID_NULL filter)
   ↓
6. Enumerate Shadow Copies (IVssEnumObject)
   ↓
7. For Each Shadow Copy:
   │
   ├─ Display: SnapshotID, VolumeName, ProviderID
   │
   └─ Call DeleteSnapshots(SnapshotID)
   ↓
8. Repeat Until No More Copies
   ↓
9. Exit
```

### Output Example

```
[i] Deleting shadow copy: {a1b2c3d4-e5f6-7890-abcd-ef1234567890} on C:\ from the provider: {b5946137-7b9f-4925-af80-51abd60b20d5}
[+] No More Shadow Copies Were Detected
```

### Error Handling

| Error Code | Message | Meaning |
|------------|---------|---------|
| `E_ACCESSDENIED` | Please Run As Admin | Insufficient privileges |
| `VSS_E_OBJECT_NOT_FOUND` | No Shadow Copies | No snapshots exist |
| Generic HRESULT | Failed: 0x[code] | VSS API error |

---

## Why This Is Used in Ransomware

### Recovery Prevention Strategy

Ransomware operators delete shadow copies to:

1. **Eliminate Restore Points**
   - Victims cannot use System Restore
   - Previous file versions are destroyed
   - Windows recovery options become useless

2. **Increase Ransom Pressure**
   - No free recovery method available
   - Victims must pay or lose data permanently
   - Backup deletion is critical to ransomware success

3. **Evade Detection** (Why This Tool Matters)
   - Traditional methods (`vssadmin delete shadows /all`) trigger alerts
   - `wmic shadowcopy delete` is heavily monitored
   - Direct API usage bypasses command-line detection

### Ransomware Families Using This Technique

- **Ryuk** - Deletes VSS before encryption
- **Conti** - Sophisticated VSS deletion routines
- **Maze** - Multi-stage shadow copy removal
- **REvil/Sodinokibi** - VSS deletion + bootloader attacks
- **LockBit** - Fast VSS removal for speed
- **BlackCat/ALPHV** - Rust-based with VSS APIs

---

## Detection & Prevention

### Behavioral Indicators

**Process Behavior:**
- Unusual COM object creation (`IVssBackupComponents`)
- VSS API calls from non-backup software
- Enumeration of all shadow copies
- Mass shadow copy deletion

**Required Privileges:**
- Must run with Administrator rights
- Requires `SeBackupPrivilege` and `SeRestorePrivilege`
- Triggers UAC if not elevated

### Detection Rules

**Sysmon Event IDs:**
- Event 1 (Process Creation) - Monitor for VSS API loading
- Event 7 (Image Loaded) - `VssApi.dll`, `ResUtils.dll` loaded by suspicious process
- Event 19/20/21 (WMI Events) - VSS-related WMI activity

**Windows Event Logs:**
- Event ID 8222 (VSS) - Shadow copy deletion
- Event ID 536 (VSS) - Shadow copy volume service errors

**EDR Telemetry:**
```
Process: unknown.exe
Loaded Modules: VssApi.dll, VSSAPI.DLL
API Calls: 
  - IVssBackupComponents::Query()
  - IVssBackupComponents::DeleteSnapshots()
Network: None (local operation)
```

### YARA Rule Example

```yara
rule Ransomware_VSS_Deletion_API {
    meta:
        description = "Detects VSS shadow copy deletion via API"
        author = "Security Researcher"
        date = "2025-01-01"
        
    strings:
        $api1 = "CreateVssBackupComponents" ascii
        $api2 = "DeleteSnapshots" ascii
        $api3 = "IVssBackupComponents" ascii
        $api4 = "VSS_CTX_ALL" ascii
        $lib1 = "VssApi.lib" ascii
        $lib2 = "ResUtils.lib" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        3 of ($api*) and 1 of ($lib*)
}
```

### Mitigation Strategies

**1. Privilege Restriction**
- Limit admin account usage
- Use standard user accounts for daily work
- Implement Just-In-Time (JIT) admin access

**2. Application Whitelisting**
- Allow only authorized backup software to access VSS APIs
- Block unknown executables from loading VssApi.dll

**3. VSS Protection**
- Enable VSS access restrictions via Group Policy
- Monitor VSS service (volsnap) integrity
- Create off-system backups (3-2-1 rule)

**4. Endpoint Detection**
- Deploy EDR with ransomware detection modules
- Alert on VSS API usage by non-standard processes
- Monitor for COM object creation patterns

**5. Network Segmentation**
- Isolate critical systems with offline backups
- Prevent lateral movement to backup servers

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description |
|-------------|----------------|-------------|
| **T1490** | **Inhibit System Recovery** | Primary technique - deletes shadow copies |
| T1106 | Native API | Uses Windows VSS APIs directly |
| T1059 | Command and Scripting Interpreter | Alternative to command-line tools |
| T1486 | Data Encrypted for Impact | Typically paired with encryption |
| T1529 | System Shutdown/Reboot | Often follows VSS deletion |

**Tactic**: Impact  
**Sub-Technique**: T1490 (Inhibit System Recovery)

---

## Code Analysis

### Critical Code Sections

**1. Admin Check:**
```cpp
hr = CreateVssBackupComponents(&m_pVssObject);
if (hr == E_ACCESSDENIED){
    printf("[!] Please Run As Admin To Delete Shadow Copies \n");
    return -1;
}
```

**2. Shadow Copy Query:**
```cpp
hr = m_pVssObject->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pIEnumSnapshots);
if (hr == VSS_E_OBJECT_NOT_FOUND) {
    printf("[i] There Is No Shadow Copies On This Machine \n");
    return -1;
}
```

**3. Deletion Loop:**
```cpp
while (TRUE){
    ULONG ulFetched;
    hr = pIEnumSnapshots->Next(1, &Prop, &ulFetched);
    if (ulFetched == 0) {
        printf("[+] No More Shadow Copies Were Detected \n");
        break;
    }
    
    hr = m_pVssObject->DeleteSnapshots(Snap.m_SnapshotId, 
                                        VSS_OBJECT_SNAPSHOT, 
                                        FALSE, 
                                        &lSnapshots, 
                                        &idNonDeletedSnapshotID);
}
```

### Comparison: Traditional vs API Method

| Method | Command | Detection Difficulty |
|--------|---------|---------------------|
| **Traditional** | `vssadmin delete shadows /all /quiet` | Easy (command-line monitoring) |
| **Traditional** | `wmic shadowcopy delete` | Easy (WMI event logs) |
| **This Tool** | Direct VSS API calls | Hard (requires API monitoring) |

---

## Forensic Artifacts

### Artifacts Left Behind

**1. Windows Event Logs:**
- **Event 8222** (VSS Provider) - "Shadow copy deleted"
- **Event 536** (VSS) - "Volume Shadow Copy Service error"

**2. Registry Keys:**
- `HKLM\SYSTEM\CurrentControlSet\Services\VSS\Diag` - VSS diagnostic info
- May contain timestamps of last shadow copy operations

**3. VSS Logs:**
- `C:\Windows\Logs\Vss\` - VSS error logs
- Check for deletion events with timestamps

**4. Prefetch Files:**
- `C:\Windows\Prefetch\[PROGRAM_NAME].pf`
- Shows program execution history

**5. Memory Artifacts:**
- COM object creation in process memory
- VSS API call stack traces
- Loaded DLL artifacts (VssApi.dll)

---

## Incident Response

### If This Tool Is Detected

**Immediate Actions:**
1. **Isolate the System**
   - Disconnect from network immediately
   - Power off if encryption is in progress
   - Do NOT reboot (preserves memory evidence)

2. **Capture Volatile Data**
   - Memory dump (use WinPMEM, DumpIt, Magnet RAM)
   - Running processes (`tasklist /v`)
   - Network connections (`netstat -ano`)

3. **Check Shadow Copy Status**
```cmd
vssadmin list shadows
wmic shadowcopy list brief
```

4. **Preserve Logs**
   - Export VSS event logs (Event ID 8222, 536)
   - Save Sysmon logs if deployed
   - Backup Security and System logs

5. **Assess Damage**
   - Check if encryption has started
   - Verify backup integrity on separate systems
   - Identify entry point (phishing email, RDP, vulnerability)

### Recovery Options

**If Shadow Copies Still Exist:**
```cmd
# List available shadow copies
vssadmin list shadows

# Restore from shadow copy
mklink /d C:\ShadowCopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy[X]\

# Copy files from shadow copy
robocopy C:\ShadowCopy\Users\[User]\Documents C:\Recovery\Documents /E
```

**If All Copies Deleted:**
- Restore from off-system backups (tape, cloud, air-gapped)
- Use file recovery tools (recuva, photorec) before encryption
- Contact professional data recovery services
- **Do NOT pay ransom** (no guarantee of decryption)

---

### ⚖️ Legal Warning

- **Unauthorized use is illegal**: Using this tool without authorization violates computer fraud laws (CFAA, Computer Misuse Act, etc.)



---

## Comparison with Other Tools

| Tool | Method | Stealth | Speed | Complexity |
|------|--------|---------|-------|-----------|
| **vssadmin** | Command-line | Low | Fast | Easy |
| **wmic** | WMI | Low | Fast | Easy |
| **PowerShell** | Scripting | Medium | Fast | Medium |
| **This Tool** | Native API | High | Fast | High |
| **Direct Driver** | Kernel-mode | Very High | Very Fast | Very High |

---

## Technical Specifications

**Compilation Requirements:**
- Visual Studio 2015+ with C++ support
- Windows SDK 10.0+
- ATL (Active Template Library)
- VSS SDK components

**Runtime Requirements:**
- Windows Vista+ (VSS 2.0+)
- Administrator privileges
- Volume Shadow Copy Service running

**Binary Characteristics:**
- Language: C++
- Architecture: x86/x64
- Imports: VssApi.dll, ResUtils.dll, Ole32.dll
- Subsystem: Console
- Typical Size: 50-100 KB (compiled)

---
