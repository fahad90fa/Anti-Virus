# Glossary

| Term | Meaning |
| --- | --- |
| Minifilter | A file-system filter driver registered with the Windows Filter Manager to intercept file I/O |
| Kernel callback | A function Windows calls on a system event (process, thread, image, registry) that a driver can register for |
| WFP | Windows Filtering Platform; the in-kernel framework for inspecting and filtering network traffic |
| ELAM | Early Launch Anti-Malware; a certified AV driver that loads before other boot-start drivers |
| Secure Boot | A UEFI firmware feature that verifies the signatures of boot components |
| PPL | Protected Process Light; a Windows protection level that shields a process from tampering, even by admins |
| PE | Portable Executable; the Windows .exe/.dll file format |
| YARA | A rule format and engine for matching byte and string patterns to identify malware |
| Heuristic | A rule-of-thumb detection based on suspicious traits rather than an exact signature |
| Behavioral detection | Judging a program by what it does at runtime, not by its file contents |
| Zero-day | A threat with no existing signature or patch, never seen before |
| Fileless malware | Malware that runs in memory or scripts, with no traditional file on disk |
| LOLBin | "Living off the land" binary; a legitimate system tool abused by malware |
| Rootkit | Malware that hides itself inside the OS or kernel |
| Bootkit | Malware that infects the boot process and runs before the OS |
| C2 | Command-and-control; the server malware communicates with |
| IOC | Indicator of compromise; an artifact (hash, IP, domain) that signals infection |
| Copy-on-write (COW) | Storing changes as a separate copy so the original stays intact until committed |
| IRP | I/O Request Packet; the structure Windows uses to pass I/O through the driver stack |
| EICAR | A harmless standard test file every AV detects, used to verify detection works |
| WDK | Windows Driver Kit; Microsoft's toolset for building drivers |
| WHQL / HLK | Windows Hardware Lab Kit certification for drivers |
| MVI | Microsoft Virus Initiative; the program that grants AV-specific privileges |
| False positive | Flagging a legitimate file or program as malicious |
| Verdict fusion | Combining multiple detection signals into one risk decision |
| AMSI | Antimalware Scan Interface; the Windows hook where scripting engines hand de-obfuscated code to a scanner |
| ETW-TI | Event Tracing for Windows Threat-Intelligence; a hook-free security telemetry feed for anti-malware |
| EDR | Endpoint detection and response; recording, investigating, and containing threats beyond simple blocking |
| BYOVD | Bring Your Own Vulnerable Driver; loading a signed-but-buggy driver to reach the kernel |
| ROP | Return-oriented programming; an exploit technique that chains fragments of existing code |
| CET | Control-flow Enforcement Technology; CPU shadow stacks that defeat ROP |
| LSASS | The Windows process holding credentials in memory; a prime theft target |
| Reflective DLL | A DLL loaded directly from memory, bypassing the normal on-disk loader |
| VBS / HVCI | Virtualization-Based Security / Hypervisor-enforced Code Integrity; hardware-isolated protection for secrets and kernel code |
| Trustlet | A small program running inside a VBS-isolated enclave (VTL1) |
| Honeytoken | A decoy credential or file that only an intruder would touch |
| Detonation | Running a suspicious file in isolation to observe its real behavior |
