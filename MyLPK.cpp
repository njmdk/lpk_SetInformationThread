#include <windows.h>
#include "DevCode.h"
#include "UsefulFunc.h"

#pragma comment(linker,"/BASE:0x62c20000")
#pragma comment(linker, "/SECTION:.text,REW" ) //设PE节：.text,可读可执行
#pragma comment(linker, "/FILEALIGN:0x200")
#pragma comment(linker, "/entry:DllMain")

typedef void  (__stdcall  * MYAPI)();


typedef int (__stdcall *pNtProtectVirtualMemory)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtWriteVirtualMemory)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtFreeVirtualMemory)(DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtOpenProcess)(DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtAllocateVirtualMemory)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtQueryVirtualMemory)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef int (__stdcall *pNtReadVirtualMemory)(DWORD, DWORD, DWORD, DWORD, DWORD);

pNtProtectVirtualMemory NtProtectVirtualMemory;
pNtWriteVirtualMemory NtWriteVirtualMemory;
pNtFreeVirtualMemory NtFreeVirtualMemory;
pNtOpenProcess NtOpenProcess;
pNtAllocateVirtualMemory NtAllocateVirtualMemory;
pNtQueryVirtualMemory NtQueryVirtualMemory;
pNtReadVirtualMemory NtReadVirtualMemory;

FARPROC CreateProcessAdd;




HMODULE lpk_module = NULL;

void ApiInit();
BOOL WINAPI NewDeviceIoControl( HANDLE hDevice, 
							   DWORD dwIoControlCode, 
							   LPVOID lpInBuffer, 
							   DWORD nInBufferSize, 
							   LPVOID lpOutBuffer, 
							   DWORD nOutBufferSize, 
							   LPDWORD lpBytesReturned, 
							   LPOVERLAPPED lpOverlapped );


MYAPI pLpkInitialize;
MYAPI pLpkTabbedTextOut;
MYAPI pLpkDllInitialize;
MYAPI pLpkDrawTextEx;
MYAPI pLpkEditControl;
MYAPI pLpkExtTextOut;
MYAPI pLpkGetCharacterPlacement;
MYAPI pLpkGetTextExtentExPoint;
MYAPI pLpkPSMTextOut;
MYAPI pLpkUseGDIWidthCache;
MYAPI pftsWordBreak;


__declspec(naked) void LpkInitialize(){__asm jmp dword ptr [pLpkInitialize]}
__declspec(naked) void LpkTabbedTextOut(){__asm jmp dword ptr [pLpkTabbedTextOut]}
__declspec(naked) void LpkDllInitialize(){__asm jmp dword ptr [pLpkDllInitialize]}
__declspec(naked) void LpkDrawTextEx(){__asm jmp dword ptr [pLpkDrawTextEx]}

__declspec(naked) void LpkExtTextOut(){__asm jmp dword ptr [pLpkExtTextOut]}
__declspec(naked) void LpkGetCharacterPlacement(){__asm jmp dword ptr [pLpkGetCharacterPlacement]}
__declspec(naked) void LpkGetTextExtentExPoint(){__asm jmp dword ptr [pLpkGetTextExtentExPoint]}
__declspec(naked) void LpkPSMTextOut(){__asm jmp dword ptr [pLpkPSMTextOut]}
__declspec(naked) void LpkUseGDIWidthCache(){__asm jmp dword ptr [pLpkUseGDIWidthCache]}
__declspec(naked) void ftsWordBreak(){
	__asm jmp dword ptr [pftsWordBreak]
		__asm nop
		__asm nop
		__asm nop
		__asm nop
}

__declspec(naked) void LpkEditControl()
{
__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm nop
__asm nop
__asm nop
__asm nop

__asm _emit 0
__asm _emit 0
__asm _emit 0
__asm _emit 0

}

void ApiInit()
{
	HMODULE ntdll_module;
	char reallpk[MAX_PATH]={0};
	GetSystemDirectoryA((LPSTR)reallpk,MAX_PATH);
	strcat(reallpk,"\\lpk.dll");
	if(lpk_module=LoadLibraryA(reallpk))
	{
		pLpkInitialize = (MYAPI) GetProcAddress(lpk_module,"LpkInitialize");
		pLpkTabbedTextOut = (MYAPI) GetProcAddress(lpk_module,"LpkTabbedTextOut");
		pLpkDllInitialize = (MYAPI) GetProcAddress(lpk_module,"LpkDllInitialize");
		pLpkDrawTextEx = (MYAPI) GetProcAddress(lpk_module,"LpkDrawTextEx");
		pLpkExtTextOut = (MYAPI) GetProcAddress(lpk_module,"LpkExtTextOut");
		pLpkGetCharacterPlacement = (MYAPI) GetProcAddress(lpk_module,"LpkGetCharacterPlacement");
		pLpkEditControl = (MYAPI) GetProcAddress(lpk_module,"LpkEditControl");
		pLpkGetTextExtentExPoint = (MYAPI) GetProcAddress(lpk_module,"LpkGetTextExtentExPoint");
		pLpkPSMTextOut = (MYAPI) GetProcAddress(lpk_module,"LpkPSMTextOut");
		pLpkUseGDIWidthCache = (MYAPI) GetProcAddress(lpk_module,"LpkUseGDIWidthCache");
		pftsWordBreak = (MYAPI) GetProcAddress(lpk_module,"ftsWordBreak");
		
		
		CopyMemory((LPVOID)((DWORD)LpkEditControl-4),(PVOID)((DWORD)pLpkEditControl-4),0x44);

		ntdll_module = (HMODULE) LoadLibraryA("ntdll.dll");
		if (ntdll_module)
		{
			NtProtectVirtualMemory = (pNtProtectVirtualMemory) GetProcAddress(ntdll_module,"NtProtectVirtualMemory");
			NtAllocateVirtualMemory = (pNtAllocateVirtualMemory) GetProcAddress(ntdll_module,"NtAllocateVirtualMemory");
			NtFreeVirtualMemory = (pNtFreeVirtualMemory) GetProcAddress(ntdll_module,"NtFreeVirtualMemory");
			NtQueryVirtualMemory = (pNtQueryVirtualMemory) GetProcAddress(ntdll_module,"NtQueryVirtualMemory");
			NtReadVirtualMemory = (pNtReadVirtualMemory) GetProcAddress(ntdll_module,"NtReadVirtualMemory");
			NtWriteVirtualMemory = (pNtWriteVirtualMemory) GetProcAddress(ntdll_module,"NtWriteVirtualMemory");
			NtOpenProcess = (pNtOpenProcess) GetProcAddress(ntdll_module,"NtOpenProcess");
		}
		else
		{
			ExitProcess(0);
		}
	}
	else
	{
		ExitProcess(0);
	}
	
}
//前五字节为被hook的代码  后五字节跳回去
BYTE g_ret2TrueSetInfo[5+5] = {0xB8, 0xE5, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00};

DWORD g_CreateProcessAddress = 0;
DWORD g_jmpCreateProcessAdd = 0;

DWORD g_CreateMutextAddress = 0;
DWORD g_jmpCreateMutexAdd = 0;
DWORD g_MyCreateMutexAddress = 0;



DWORD g_CreateFileAddress = 0;
DWORD g_MyCreateFileAddress = 0;
DWORD g_jmpCreateFileAdd = 0;

#include <stdio.h>

void main()
{

}

DWORD
WINAPI
MyNtSetInformationThread(
						 IN HANDLE ThreadHandle,
						 IN DWORD ThreadInformationClass,
						 IN PVOID ThreadInformation,
						 IN ULONG ThreadInformationLength
						 )
{
	DWORD dwRet;
	
	if (ThreadInformationClass == 17)
	{
		//HideFromDebugger
		return 1;
	}
	__asm
	{
		PUSH   ThreadInformationLength
			PUSH   ThreadInformation
			PUSH   ThreadInformationClass
			PUSH   ThreadHandle
			LEA    EAX,  g_ret2TrueSetInfo
			CALL   EAX
			MOV    dwRet, EAX
	}
	return dwRet;
}

char* pexename = NULL;
char exename[32] = {'G','a','m','e','M','o','n','.','d','e','s'};
char mutex1[32] = {'N','L','5','9','N','P','G','L'};
char mutexNPGL[32] = {'G','l','o','b','a','l','\\','M','t','x','N','P','G','L'};
char mutexNPGM[32] = {'G','l','o','b','a','l','\\','M','t','x','N','P','G','M'};
BYTE fix1[0x06] = {0x83,0xC4,0x28,0x90,0x90,0x90};
DWORD dwOldProtect;
DWORD dwFixAdd = 0;
DWORD dwMutexAdd = 0x9F997C;
DWORD dwCreateMutexA = 0xF57028;
HANDLE dwMtxNPGL = 0;
HANDLE dwNLNPGL = 0;
HANDLE hMutex = NULL;
char dllfile[MAX_PATH];

BOOL PatchNP();
BOOL InJob(HANDLE hProcss,char * lpDLLName,UINT pid);
BOOL HookCreateMutexA();
__declspec(naked) void MyCreateMutexA()
{
	__asm{
			mov eax,0x15
			retn 0x0c
	}
}
/*__declspec(naked) void MyCreateMutexA()
{
	__asm{
		mov eax,esp
		mov eax,DWORD ptr[eax]
NL59NPGL:
		cmp eax,0x90C80D
		jnz MtxNPGL
		mov eax,g_CreateMutextAddress
		add eax,2
		mov BYTE ptr[eax],0x55
		add eax,1
		mov DWORD ptr[eax],0x5151EC8B
		push DWORD ptr[esp+0x0C]
		push DWORD ptr[esp+0x0C]
		push DWORD ptr[esp+0x0C]
		mov eax,0xF57028
		mov eax,DWORD ptr[eax]
		call eax
		mov dwNLNPGL,eax
		mov eax,g_CreateMutextAddress
		add eax,2
		mov BYTE ptr[eax],0xE9
		add eax,1
		push edx
		mov edx,g_MyCreateMutexAddress
		mov DWORD ptr[eax],edx
		pop edx
		mov eax,dwNLNPGL
		retn 0x0C
MtxNPGL:
		cmp eax,0x910064
		jnz MtxNPGM
		mov eax,g_CreateMutextAddress
		add eax,2
		mov BYTE ptr[eax],0x55
		add eax,1
		mov DWORD ptr[eax],0x5151EC8B
		push DWORD ptr[esp+0x0C]
		push DWORD ptr[esp+0x0C]
		push DWORD ptr[esp+0x0C]
		mov eax,0xF57028
		mov eax,DWORD ptr[eax]
		call eax
		mov dwMtxNPGL,eax
		mov eax,g_CreateMutextAddress
		add eax,2
		mov BYTE ptr[eax],0xE9
		add eax,1
		push edx
		mov edx,g_MyCreateMutexAddress
		mov DWORD ptr[eax],edx
		pop edx
		mov eax,dwMtxNPGL
		retn 0x0C
MtxNPGM:
		cmp eax,0x910184
		jnz end
		mov eax,g_CreateMutextAddress
		add eax,2
		mov BYTE ptr[eax],0x55
		add eax,1
		mov DWORD ptr[eax],0x5151EC8B

		mov eax,dwMutexAdd
		mov eax,DWORD ptr[eax]
		push eax
		mov eax,CloseHandle
		call eax
		mov eax,dwMutexAdd
		mov DWORD ptr[eax],0

		mov eax,dwNLNPGL
		push eax
		mov eax,CloseHandle
		call eax
		mov dwNLNPGL,0

		mov eax,dwMtxNPGL
		push eax
		mov eax,CloseHandle
		call eax
		mov dwMtxNPGL,0
		//call PatchNP
end:
		push ebp
		mov ebp,esp
		push ecx
		push ecx
		jmp [g_jmpCreateMutexAdd]
	}
}*/
BOOL PatchNP()
{
	OutputDebugString("start fix!");
	
// 	dwFixAdd = 0x90E5EE;
// 	VirtualProtect(LPVOID(dwFixAdd),6 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	memcpy(LPVOID(dwFixAdd),fix1,0x06);
	
	dwFixAdd = 0x449eb5;
	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE *)(dwFixAdd) = 0x85;
	
	dwFixAdd = 0x44ad1f;
	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE *)(dwFixAdd) = 0xEB;
	
	dwFixAdd = 0x9cfafb;
	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE *)(dwFixAdd) = 0xEB;
	
	dwFixAdd = 0x9d2c47;
	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE *)(dwFixAdd) = 0xEB;
	
// 	dwFixAdd = 0x46903a;
// 	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	*(BYTE *)(dwFixAdd) = 0xEB;
// 	dwFixAdd = 0x46909a;
// 	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	*(BYTE *)(dwFixAdd) = 0xEB;
// 	dwFixAdd = 0x4692bb;
// 	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	*(BYTE *)(dwFixAdd) = 0xEB;
// 	
// 	dwFixAdd = 0x920495;
// 	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	*(BYTE *)(dwFixAdd) = 0xEB;
// 	dwFixAdd = 0x923ddf;
// 	VirtualProtect(LPVOID(dwFixAdd),1 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
// 	*(BYTE *)(dwFixAdd) = 0xEB;
	OutputDebugString("fix ok");
	return TRUE;
}
BOOL InJob(HANDLE hProcss,char * lpDLLName,UINT pid)
{
	if(hProcss == NULL) 
		return FALSE;
	if(strlen(lpDLLName) <= 4 )
		return FALSE;
	int cb = (1 + lstrlen(lpDLLName)) * sizeof(CHAR); 
	int memsize = cb;
	PVOID StartAddress = NULL;
	PWSTR pszLibFileRemote = (PWSTR) VirtualAllocEx(hProcss, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
	
	if(pszLibFileRemote == NULL)
	{
		OutputDebugString("分配内存失败");
		return FALSE;
	}
	//写进程数据，如果这儿失败可以有WPM函数替换
	BOOL iReturnCode = WriteProcessMemory(hProcss, pszLibFileRemote, (PVOID) lpDLLName, cb, NULL);
	if(!iReturnCode/*!WPM(pid,pszLibFileRemote,lpDLLName,cb)*/)
	{
		char outbuf[20];
		sprintf(outbuf,("%X"),pszLibFileRemote);
		OutputDebugString(outbuf);
		return FALSE;
	}
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");  
	//405A5E
	//HANDLE hRemoteThread = CreateRemoteThread( hProcss, NULL, 0, pfnStartAddr, pszLibFileRemote, 0, NULL);
	HANDLE hRemoteThread = CreateRemoteThread( hProcss, NULL, 0, pfnStartAddr, pszLibFileRemote, 0, NULL);
	if(hRemoteThread == NULL) 
	{
		OutputDebugString("创建线程失败");
		return FALSE;
	}
	Sleep(100);
	CloseHandle(hRemoteThread);
	return TRUE;
}
BOOL CreateProcessRetBool = FALSE;
__declspec(naked) void MyCreateProcessA()
{
	__asm{
		push ebp
		mov ebp,esp
		mov eax,dword ptr[ebp+0x04]

STARTNP:
 		cmp eax,0x9d1e57
 		jnz END
// 		call PatchNP
// 		mov esp,ebp
// 		pop ebp
// 		mov eax,1
// 		retn 0x28
		//---------------------------------------------
		//pushad
		mov eax,dword ptr[ebp+0x2C]
		push eax
		mov eax,dword ptr[ebp+0x28]
		push eax
		mov eax,dword ptr[ebp+0x24]
		push eax
		mov eax,dword ptr[ebp+0x20]
		push eax
		mov eax,dword ptr[ebp+0x1C]
		push eax
		mov eax,dword ptr[ebp+0x18]
		push eax
		mov eax,dword ptr[ebp+0x14]
		push eax
		mov eax,dword ptr[ebp+0x10]
		push eax
		mov eax,dword ptr[ebp+0x0C]
		push eax
		mov eax,dword ptr[ebp+0x08]
		push eax

		mov eax,g_CreateProcessAddress
		add eax,2
		mov byte ptr[eax],0x55
		add eax,1
		mov word ptr[eax],0xec8b
		add eax,2
		mov word ptr[eax],0x006a

		mov eax,g_CreateProcessAddress
		call eax
		
		mov CreateProcessRetBool,eax
		mov eax,dword ptr[ebp+0x2C]
		mov eax,dword ptr[eax+0x08]
		push eax
		lea eax,dllfile
		push eax
		mov eax,dword ptr[ebp+0x2C]
		mov eax,dword ptr[eax]
		push eax
		call InJob
		add esp,0x0C
		//popad
		mov esp,ebp
		pop ebp
		mov eax,CreateProcessRetBool
		retn 0x28
		//---------------------------------------------
END:
		mov esp,ebp
		pop ebp

		push ebp
		mov ebp,esp
		push 0
		jmp [g_jmpCreateProcessAdd]
	}
}

BOOL HookCreateMutexA()
{
	while (!GetModuleHandle("kernel32.dll"))
	{
		Sleep (500);
	}
	g_CreateMutextAddress = (DWORD)GetProcAddress (GetModuleHandle("kernel32.dll"), "CreateMutexA");
	if (g_CreateMutextAddress == 0)
	{
		OutputDebugString("dwHookAddr error");
		return FALSE;
	}
	g_MyCreateMutexAddress = (DWORD)MyCreateMutexA - (g_CreateMutextAddress+2) - 5;
	g_jmpCreateMutexAdd = (g_CreateMutextAddress+5+2);//跳转返回地址
	
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_CreateMutextAddress+2),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE*)(g_CreateMutextAddress+2) = 0xE9;
	*(DWORD*)(g_CreateMutextAddress+3) = g_MyCreateMutexAddress;
	
	OutputDebugString("Hook CreateMutexA ok");
	return TRUE;
}

DWORD g_GetCurrentProcessAddress = 0;
DWORD g_jmpGetCurrentProcessAdd = 0;
BYTE g_OldCode[10] = {0};
BOOL HookGetCurrentProcess();
HANDLE WINAPI MyGetCurrentProcess();
BOOL HookGetCurrentProcess()
{
	while (!GetModuleHandle("kernel32.dll"))
	{
		Sleep (500);
	}
	g_GetCurrentProcessAddress = (DWORD)GetProcAddress (GetModuleHandle("kernel32.dll"), "GetCurrentProcess");
	if (g_GetCurrentProcessAddress == 0)
	{
		OutputDebugString("dwHookAddr error");
		return FALSE;
	}
	g_OldCode[0] = *(BYTE*)g_GetCurrentProcessAddress;
	*(DWORD*)(g_OldCode+1) = *(DWORD*)(g_GetCurrentProcessAddress+1);
	
	DWORD tmp = (DWORD)MyGetCurrentProcess - g_GetCurrentProcessAddress - 5;
	
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_GetCurrentProcessAddress),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE*)(g_GetCurrentProcessAddress) = 0xE9;
	*(DWORD*)(g_GetCurrentProcessAddress+1) = tmp;
	
	OutputDebugString("Hook GetCurrentProcess ok");
	return TRUE;
}

HANDLE WINAPI MyGetCurrentProcess()
{
	HMODULE hMod=GetModuleHandle("npggNT.des");
	if(hMod != NULL)
	{
		FreeLibrary(hMod);      //直接Free掉它
		OutputDebugString("Free npggNT.des ok");
		//AfxMessageBox("Free npggNT.des ok");
	}
	*(BYTE*)(g_GetCurrentProcessAddress) = g_OldCode[0];
	*(DWORD*)(g_GetCurrentProcessAddress+1) = *(DWORD*)(g_OldCode+1);
	HANDLE hProcess=GetCurrentProcess();//让它调用 
	HookGetCurrentProcess();//重新挂钩 
	return hProcess;   //返回调用结果 
}
BOOL HookCreateProcessA()
{
	BYTE jmp_codes[5] = {0xE9, 0, 0, 0, 0};
	
	while (!GetModuleHandle("kernel32.dll"))
	{
		Sleep (500);
	}
	g_CreateProcessAddress = (DWORD)GetProcAddress (GetModuleHandle("kernel32.dll"), "CreateProcessA");
	if (g_CreateProcessAddress == 0)
	{
		OutputDebugString("dwHookAddr error");
		return FALSE;
	}
	DWORD tmp = (DWORD)MyCreateProcessA - (g_CreateProcessAddress+2) - 5;
	g_jmpCreateProcessAdd = (g_CreateProcessAddress+5+2);//跳转返回地址
	
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_CreateProcessAddress+2),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE*)(g_CreateProcessAddress+2) = 0xE9;
	*(DWORD*)(g_CreateProcessAddress+3) = tmp;
	
	OutputDebugString("Hook CreateProcessA ok");
	return TRUE;
}
__declspec(naked) void MyCreateFileA()
{
	__asm mov eax,esp
	__asm add eax,4
	__asm mov eax,DWORD ptr[eax]
	__asm mov pexename,eax
	
	if(strstr(pexename,"CabalOnlineUS.ini") != 0)
	{
		__asm int 3
	}

	__asm{
		mov ebp,esp
		push DWORD ptr[ebp+8]
		jmp [g_jmpCreateFileAdd]
	}
}
BOOL HookCreateFileA()
{
	BYTE jmp_codes[5] = {0xE9, 0, 0, 0, 0};
	
	while (!GetModuleHandle("kernel32.dll"))
	{
		Sleep (500);
	}
	g_CreateFileAddress = (DWORD)GetProcAddress (GetModuleHandle("kernel32.dll"), "CreateFileA");
	if (g_CreateFileAddress == 0)
	{
		OutputDebugString("dwHookAddr error");
		return FALSE;
	}
	DWORD tmp = (DWORD)MyCreateFileA - (g_CreateFileAddress+3) - 5;
	g_jmpCreateFileAdd = (g_CreateFileAddress+5+3);//跳转返回地址
	
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_CreateFileAddress+3),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE*)(g_CreateFileAddress+3) = 0xE9;
	*(DWORD*)(g_CreateFileAddress+4) = tmp;
	
	OutputDebugString("Hook CreateFileA ok");
	return TRUE;
}

void HookGameMonMsg();
void MyGameMonMsg();
void UnHookGameMonMsg();
void CallNP(BYTE* npData);
DWORD g_HookGameMonMsgAddress = 0x43e8b7;
DWORD g_HookGameMonMsgRet = 0;
DWORD g_OldGameMon = 0;
BYTE g_GameMonMsgOldCode[10] = {0};
void HookGameMonMsg()
{
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_HookGameMonMsgAddress),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	g_GameMonMsgOldCode[0] = *(BYTE*)g_HookGameMonMsgAddress;
	*(DWORD*)(g_GameMonMsgOldCode+1) = g_OldGameMon = *(DWORD*)(g_HookGameMonMsgAddress+1);
	*(BYTE*)g_HookGameMonMsgAddress = 0xE9;
	DWORD tmp = (DWORD)UnHookGameMonMsg - g_HookGameMonMsgAddress - 5;
	*(DWORD*)(g_HookGameMonMsgAddress+1) = tmp;
	
	g_HookGameMonMsgRet = g_HookGameMonMsgAddress+5;//跳回地址
}
__declspec(naked) void UnHookGameMonMsg()
{
	__asm
	{
		mov eax,g_HookGameMonMsgAddress
			mov byte ptr[eax],0xB8
			add eax,1
			mov dword ptr[eax],0x43e55b
			mov eax,MyGameMonMsg
			jmp dword ptr[g_HookGameMonMsgRet]
	}
}
DWORD dwNpData = 0;

HANDLE hPipe;
BYTE  sendbuf[0x400];
DWORD dwRead;
__declspec(naked) void MyGameMonMsg()
{
	__asm mov eax,dword ptr[esp+4]
		__asm mov eax,dword ptr[eax]
		__asm mov eax,dword ptr[eax+0x20]
		__asm mov eax,dword ptr[eax+0x04]
		__asm mov dword ptr[dwNpData],eax
		__asm pushad
		memcpy(sendbuf,(char*)dwNpData,*(DWORD*)dwNpData+8);
	if(!WriteFile(hPipe,sendbuf,0x400,&dwRead,NULL))
	{
		DisconnectNamedPipe(hPipe);
	}
	__asm popad
		__asm
	{
		jmp dword ptr[g_OldGameMon]
	}
}
BYTE np[0x38] = {0};
void CallNP(BYTE* npData)
{
	memset(np,0,sizeof(np));
	*(DWORD*)(np+4) = (DWORD)npData;
	*(DWORD*)(np+0x3C) = (DWORD)npData;
	*(DWORD*)(np+8) = *(DWORD*)npData+4;
	*(DWORD*)(np+0x0c) = *(DWORD*)npData+4;
	__asm
	{
		mov eax,0x43e316
			push np
			call eax
			add esp,4
	}
}

DWORD g_SetWindowsHookAddress;
DWORD g_jmpSetWindowsHookAdd;

__declspec(naked) void MySetWindowsHookExA()
{
	__asm
	{
		mov eax,dword ptr[esp+4]
		cmp eax,9
		jnz nextcheck
		mov eax,1000
		retn 0x10
nextcheck:
		cmp eax,13
		jnz nextend
		mov eax,dword ptr[g_SetWindowsHookAddress]
		mov byte ptr[eax],0x8B
		mov dword ptr[eax+1],0xec8b55ff
		mov eax,1000
		retn 0x10
nextend:
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp dword ptr[g_jmpSetWindowsHookAdd]
	}
}
BOOL HookSetWindowsHookExA()
{
	BYTE jmp_codes[5] = {0xE9, 0, 0, 0, 0};
	
	while (!GetModuleHandle("User32.dll"))
	{
		Sleep (500);
	}
	g_SetWindowsHookAddress = (DWORD)GetProcAddress (GetModuleHandle("User32.dll"), "SetWindowsHookExA");
	if (g_SetWindowsHookAddress == 0)
	{
		OutputDebugString("dwHookAddr error");
		return FALSE;
	}
	DWORD tmp = (DWORD)MySetWindowsHookExA - g_SetWindowsHookAddress - 5;
	g_jmpSetWindowsHookAdd = (g_SetWindowsHookAddress+5);//跳转返回地址

	DWORD dwOldProtect;
	VirtualProtect(LPVOID(g_SetWindowsHookAddress),5 , PAGE_EXECUTE_READWRITE ,&dwOldProtect);
	*(BYTE*)(g_SetWindowsHookAddress) = 0xE9;
	*(DWORD*)(g_SetWindowsHookAddress+1) = tmp;
	
	//OutputDebugString("Hook CreateProcessA ok");
	return TRUE;
}
DWORD WINAPI thread_Hook(LPVOID lparam)
{
 	char modname[MAX_PATH] = {0};
 	GetModuleFileName(NULL,modname,MAX_PATH);
 	//if(strstr(modname,"china_login.mpr"))
	if(strstr(modname,"a_3OnlineClient.exe"))
 	{
 		//HookSetWindowsHookExA();
		HookCreateMutexA();
		return 0;
 	}
	DWORD add = 0x4010A8;
	DWORD dwOldProtect;
	if(strstr(modname,"3Online.exe"))
	{
		if(VirtualProtect(LPVOID(add),1,PAGE_EXECUTE_READWRITE,&dwOldProtect))
		{
			*(BYTE*)(add) = 0xEB;
		}
		return 1;
 	}
	//HookCreateProcessA();
	return 1;

// 	BYTE jmp_codes[5] = {0xE9, 0, 0, 0, 0};
// 
// 	while (!GetModuleHandle("ntdll.dll"))
// 	{
// 		Sleep (500);
// 	}
// 	DWORD dwHookAddr = (DWORD)GetProcAddress (GetModuleHandle("ntdll.dll"), "NtSetInformationThread");
// 	if (dwHookAddr == 0)
// 	{
// 		OutputDebugString("dwHookAddr error");
// 		return FALSE;
// 	}
// 	DWORD tmp = (DWORD)MyNtSetInformationThread - dwHookAddr - 5;
// 	memcpy (jmp_codes+1, &tmp, 4);		//加上跳转地址
// 	tmp = (dwHookAddr+5) - (DWORD)(g_ret2TrueSetInfo+5) - 5;
// 	memcpy (g_ret2TrueSetInfo+5+1, &tmp, 4);		//跳转返回地址
// 
// 	if (!WriteProcessMemory ((HANDLE)-1, (PVOID)dwHookAddr, jmp_codes, 5, &tmp))
// 	{
// 		OutputDebugString("NtSetInformationThread hook error");
// 		return FALSE;
// 	}
// 	
// 	OutputDebugString("Hook ok");
}


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			char filename[MAX_PATH];
			char textinfo[MAX_PATH];
			GetModuleFileName(NULL,filename,MAX_PATH);
			strcpy(dllfile,filename);
			strcpy(textinfo,filename);
			strcat(textinfo," Lpk.dll: process_attach!");
			OutputDebugString(textinfo);
			int len = strlen(dllfile);
			for (int i=len-1;i>=0;i--)
			{
				if(dllfile[i] == '\\')
				{
					dllfile[i] = 0;
					break;
				}
			}
			//strcat(dllfile,"\\God.dll");
			//OutputDebugString("Lpk.dll: process_attach");
			ApiInit();
			CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE)thread_Hook, NULL, 0, 0);
		}
		break;
	case DLL_PROCESS_DETACH:
		{
			char filename[MAX_PATH];
			char textinfo[MAX_PATH];
			GetModuleFileName(NULL,filename,MAX_PATH);
			strcpy(textinfo,filename);
			strcat(textinfo," Lpk.dll: process_detach!");
			OutputDebugString(textinfo);
			//OutputDebugString("Lpk.dll: process_detach");
		}
		break;
	case DLL_THREAD_ATTACH:

		break;
	case DLL_THREAD_DETACH:

		break;
	}
    return TRUE;
}

