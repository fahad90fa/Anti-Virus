# Kernel debugging setup (WinDbg)

Attach a kernel debugger before loading any new Sentinel driver build so a bug
surfaces in WinDbg instead of a bare bugcheck.

## Network kernel debugging (recommended, Gen-2 VM)

Inside the test VM:

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<HOST-IP> port:50000 key:1.2.3.4
# reboot
```

On the host, launch WinDbg:

```
windbg -k net:port=50000,key=1.2.3.4
```

## Useful commands once attached

```
!analyze -v            ; triage a bugcheck
fltkd.fltmgr           ; minifilter state (needs the fltmgr extension)
!process 0 0           ; process list (cross-view sanity)
lm                     ; loaded modules (is our driver present + signed?)
.reload /f             ; reload symbols
```

## Loading / unloading drivers in the VM

```cmd
:: minifilters (fsfilter, shadowfs) via fltmc
sc create SentinelFs type= filesystem binPath= C:\sentinel\fsfilter.sys
fltmc load SentinelFs
fltmc unload SentinelFs

:: callback / WFP drivers
sc create SentinelProc type= kernel binPath= C:\sentinel\procmon.sys
sc start SentinelProc
sc stop SentinelProc && sc delete SentinelProc
```

Always revert to the `Clean` snapshot between test runs.
