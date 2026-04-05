POC to use the Sapera Memory Manager driver "CorMem.sys" (40c855d20d497823716a08a443dc85846233226985ee653770bc3b245cf2ed0f) to elevate from an unprivileged user to NT AUTHORITY\SYSTEM and to terminate protected (PPL) processes (such as MsMpEng.exe or EDRs).

To build: `x86_64-w64-mingw32-g++ -O2 -o poc.exe poc.cpp -lntdll -static 2>&1`

To elevate: `poc.exe elevate`
To terminate a process `poc.exe kill 1212` or `poc.exe kill msmpeng.exe`