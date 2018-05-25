#include"pestudy.h"
using namespace std;




BOOL Readprocess(PCHAR dest_process, PVOID &buffer) {
	DWORD filesize;
	DWORD sizeread;
	HANDLE hFile = CreateFileA(dest_process, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	filesize = GetFileSize(hFile,NULL);
	buffer = new BYTE[filesize];
	ReadFile(hFile, buffer, filesize, &sizeread, NULL);
	CloseHandle(hFile);
	return TRUE;
}
BOOL CheckAndSet(PVOID buffer, PE &pe) {
	pe.dos_header = (PIMAGE_DOS_HEADER)buffer;
	if (pe.dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	pe.nt_headers = (PIMAGE_NT_HEADERS)((BYTE *)buffer + pe.dos_header->e_lfanew);
	if (pe.nt_headers->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	pe.file_header = &(pe.nt_headers->FileHeader);
	pe.op_header = &(pe.nt_headers->OptionalHeader);
	pe.sectionheader = (PIMAGE_SECTION_HEADER)((CHAR *)(pe.op_header) + pe.file_header->SizeOfOptionalHeader);
	return TRUE;
}
BOOL PrintEverything(PE &pe) {
	cout << ::hex;
	cout << "**************************************" << endl;
	cout << "\t\t\tDOS_HEADER" << endl;
	cout << "**************************************" << endl;
	cout << "pe.dos_header->e_magic\t" << pe.dos_header->e_magic << endl;
	cout << "pe.dos_header->e_cblp\t" << pe.dos_header->e_cblp << endl;
	cout << "pe.dos_header->e_cp\t" << pe.dos_header->e_cp << endl;
	cout << "pe.dos_header->e_crlc\t" << pe.dos_header->e_crlc << endl;
	cout << "pe.dos_header->e_lfanew\t" << pe.dos_header->e_lfanew << endl;
	cout << "**************************************" << endl;
	cout << "\t\t\FILE_HEADER" << endl;
	cout << "**************************************" << endl;
	cout << "pe.file_header->Machine\t" << pe.file_header->Machine << endl;
	cout << "pe.file_header->NumberOfSections\t" << pe.file_header->NumberOfSections << endl;
	cout << "pe.file_header->TimeDateStamp\t" << pe.file_header->TimeDateStamp << endl;
	cout << "pe.file_header->SizeOfOptionalHeader\t" << pe.file_header->SizeOfOptionalHeader << endl;
	cout << "pe.file_header->Characteristics\t" << pe.file_header->Characteristics << endl;
	cout << "**************************************" << endl;
	cout << "\t\t\OPTIONAL_HEADER" << endl;
	cout << "**************************************" << endl;
	cout << "pe.op_header->Magic\t" << pe.op_header->Magic << endl;
	cout << "pe.op_header->MajorLinkerVersion\t" << (int)pe.op_header->MajorLinkerVersion << endl;
	cout << "pe.op_header->SizeOfHeapCommit\t" << pe.op_header->SizeOfHeapCommit << endl;
	cout << "pe.op_header->LoaderFlags\t" << pe.op_header->LoaderFlags << endl;
	cout << "pe.op_header->NumberOfRvaAndSizes\t" << pe.op_header->NumberOfRvaAndSizes << endl;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		cout << "DataDirectory" << i << "\t" << pe.op_header->DataDirectory[i].VirtualAddress << "\t" << pe.op_header->DataDirectory[i].Size<< endl;
	}
	cout << "**************************************" << endl;
	cout << "\t\t\SECTION_HEADER" << endl;
	cout << "**************************************" << endl;
	PIMAGE_SECTION_HEADER p = pe.sectionheader;
	for (int i = 0; i < pe.file_header->NumberOfSections; i++) {
		cout << "SECTION" << i + 1 << ":"<< endl;
		
		cout << "Misc.VirtualSize:\t" << p->Misc.VirtualSize << endl;
		cout << "VirtualAddress:\t" << p->VirtualAddress << endl;
		cout << "SizeOfRawData:\t" << p->SizeOfRawData << endl;
		cout << "PointerToRawData:\t" << p->PointerToRawData << endl;
		cout << "PointerToRelocations:\t" << p->PointerToRelocations << endl;
		cout << "PointerToLinenumbers:\t" << p->PointerToLinenumbers << endl;
		cout << "NumberOfRelocations:\t" << p->NumberOfRelocations << endl;
		cout << "NumberOfLinenumbers:\t" << p->NumberOfLinenumbers << endl;
		cout << "Characteristics:\t" << p->Characteristics << endl;
		p++;
	}
	cout << dec;
	return TRUE;
}

BOOL PrintImport(PE pe) {
	DWORD RVA, FA;
	RVA = pe.op_header->DataDirectory[1].VirtualAddress;
	RVAtoFA(pe, RVA, FA);
	PIMAGE_IMPORT_DESCRIPTOR p = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pe.dos_header + FA);
	PIMAGE_THUNK_DATA q = NULL;
	cout << "**************************************" << endl;
	cout << "\t\t\IMPORT_TABLE" << endl;
	cout << "**************************************" << endl;
	while (p->Characteristics | p->FirstThunk | p->ForwarderChain | p->Name) {
		RVAtoFA(pe, p->Name, FA);
		cout << "DLL NAME:\t" << (char *)(FA+(BYTE *)pe.dos_header) << endl;
		cout << "TimeStamp:\t" << hex << p->TimeDateStamp << endl;
		RVAtoFA(pe, p->OriginalFirstThunk, FA);
		q = (PIMAGE_THUNK_DATA)((BYTE *)pe.dos_header+FA);
		//cout << "导入函数序号\t" << "导入函数名称" << endl;
		while (q->u1.Ordinal) {
			if (q->u1.Ordinal & 0x80000000) {
				cout<<"序号：" << (q->u1.Ordinal & 0x7FFFFFFF) << endl;
			}
			else {
				RVAtoFA(pe, q->u1.Ordinal & 0x7FFFFFFF, FA);
				cout <<"Hint:"<<hex<< *(PWORD)(FA + (BYTE *)pe.dos_header) <<"\tNAME:"<<(char *)(FA+(BYTE *)pe.dos_header+2) << endl;
			}
			q++;
		}


		p++;
		cout << endl;
	}
	
	return TRUE;
}

BOOL RVAtoFA(PE pe, DWORD RVA, DWORD &FA) {
	PIMAGE_SECTION_HEADER p = pe.sectionheader;
	DWORD numofsection = pe.file_header->NumberOfSections;
	if (RVA < p->VirtualAddress) {
		FA = RVA;
		return TRUE;
	}
	for (int i = 0; i < numofsection-1; i++) {
		if ((RVA > p->VirtualAddress)&(RVA < (p + 1)->VirtualAddress)) {
			FA = p->PointerToRawData + RVA - p->VirtualAddress;
			return TRUE;
		}
		p++;
	}
	if (RVA < (p->VirtualAddress + p->Misc.VirtualSize)) {
		FA= p->PointerToRawData + RVA - p->VirtualAddress;
		return TRUE;
	}
	return FALSE;
}
BOOL FAtoRVA(PE pe, DWORD &RVA, DWORD FA) {
	PIMAGE_SECTION_HEADER p = pe.sectionheader;
	DWORD numofsection = pe.file_header->NumberOfSections;
	if (FA < p->PointerToRawData) {
		RVA = FA;
		return TRUE;
	}
	for (int i = 0; i > numofsection-1; i++) {
		if ((FA > p->PointerToRawData)&(FA < (p + 1)->PointerToRawData)) {
			RVA = FA - p->PointerToRawData + p->VirtualAddress;
			return TRUE;
		}
		p++;
	}
	if (RVA < (p->PointerToRawData + p->SizeOfRawData)) {
		RVA = FA - p->PointerToRawData + p->VirtualAddress;
		return TRUE;
	}
	return FALSE;
}
BOOL PrintExport(PE pe) {
	DWORD RVA, FA;
	RVAtoFA(pe, pe.op_header->DataDirectory[0].VirtualAddress, FA);
	PIMAGE_EXPORT_DIRECTORY pexport = (PIMAGE_EXPORT_DIRECTORY)(FA+(BYTE *)pe.dos_header);
	
	if (pexport->AddressOfFunctions==NULL) {
		cout << "No export!" << endl;
		return FALSE;
	}
	cout << "**************************************" << endl;
	cout << "\t\t\EXPORT_TABLE" << endl;
	cout << "**************************************" << endl;
	RVAtoFA(pe, pexport->Name, FA);
	cout <<"NAME:\t\t"<< (char*)(FA + (BYTE *)pe.dos_header) << endl;
	RVAtoFA(pe, pexport->AddressOfFunctions, FA);
	DWORD * addf = (DWORD *)(FA + (BYTE *)pe.dos_header);
	RVAtoFA(pe, pexport->AddressOfNames, FA);
	DWORD * addn = (DWORD *)(FA + (BYTE *)pe.dos_header);
	RVAtoFA(pe, pexport->AddressOfNameOrdinals, FA);
	WORD * addo = (WORD *)(FA + (BYTE *)pe.dos_header);


	DWORD* ex = new DWORD[pexport->NumberOfFunctions*3];
	ZeroMemory(ex,pexport->NumberOfFunctions * 3*sizeof(DWORD));//0 bianhao; 1 dizhi; 2 mingchen;
	for (int i = 0; i < pexport->NumberOfFunctions; i++) {
		ex[i * 3 + 1] = addf[i];
		//ex[i * 3] = i;
	}
	for (int i = 0; i < pexport->NumberOfNames; i++) {
		ex[addo[i] * 3] = addo[i];
		ex[addo[i] * 3 + 2] = addn[i];
	}
	cout << "编号\t 地址\t 名称" << endl;
	for (int i = 0; i < pexport->NumberOfFunctions; i++) {
		cout << hex << ex[i * 3] << "\t" << ex[3 * i + 1]<<"\t";
		if (ex[3 * i + 2] == NULL) {
			cout << endl;
		}
		else {
			RVAtoFA(pe, ex[i * 3 + 2], FA);
			cout << (char *)(FA + (BYTE *)pe.dos_header) << endl;
		}
	}
	

	delete[]ex;
	
	return TRUE;
}
BOOL Writeprocess(PCHAR filename, PVOID buffer, PE pe) {
	HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	PIMAGE_SECTION_HEADER psection = pe.sectionheader;
	psection += pe.file_header->NumberOfSections - 1;
	
	DWORD filesize = psection->PointerToRawData + psection->SizeOfRawData;
	DWORD writesize = 0;
	WriteFile(hFile, buffer, filesize, &writesize, NULL);
	CloseHandle(hFile);
	return TRUE;
}
BOOL AddSection(PE &pe,PVOID &buffer) {
	PBYTE src = (BYTE *)pe.dos_header + pe.dos_header->e_lfanew;
	pe.dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	PBYTE dest = ((BYTE *)pe.dos_header + pe.dos_header->e_lfanew);
	DWORD copsize = pe.op_header->SizeOfHeaders - (src - dest);
	memcpy(dest, src, copsize);//将pe头上移
	pe.nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)pe.nt_headers - (src - dest));
	pe.file_header = (PIMAGE_FILE_HEADER)((PBYTE)pe.file_header - (src - dest));
	pe.op_header = (PIMAGE_OPTIONAL_HEADER)((PBYTE)pe.op_header - (src - dest));
	pe.sectionheader = (PIMAGE_SECTION_HEADER)((PBYTE)pe.sectionheader - (src - dest));//重新设置pe结构
	PIMAGE_SECTION_HEADER p= pe.sectionheader;
	p += pe.file_header->NumberOfSections;
	p->Characteristics = (p - 1)->Characteristics;
	p->SizeOfRawData = (p - 1)->SizeOfRawData;
	p->Misc.VirtualSize = (p - 1)->SizeOfRawData;
	p->Name[0] = '.';
	p->Name[1] = 'M';
	p->Name[2] = 'y';
	p->VirtualAddress = (p - 1)->VirtualAddress + (p - 1)->SizeOfRawData;
	p->PointerToRawData = (p - 1)->PointerToRawData + (p - 1)->SizeOfRawData;
	pe.op_header->SizeOfImage += p->Misc.VirtualSize;
	PBYTE newbuffer = new BYTE[p->PointerToRawData + p->SizeOfRawData];//放到更大的堆栈中
	ZeroMemory(newbuffer, p->PointerToRawData + p->SizeOfRawData);
	memcpy(newbuffer, buffer, (p - 1)->PointerToRawData + (p - 1)->SizeOfRawData);
	pe.dos_header = (PIMAGE_DOS_HEADER)((PBYTE)pe.dos_header - buffer + newbuffer);
	pe.nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)pe.nt_headers - buffer + newbuffer);
	pe.file_header = (PIMAGE_FILE_HEADER)((PBYTE)pe.file_header - buffer + newbuffer);
	pe.op_header = (PIMAGE_OPTIONAL_HEADER)((PBYTE)pe.op_header - buffer + newbuffer);
	pe.sectionheader = (PIMAGE_SECTION_HEADER)((PBYTE)pe.sectionheader - buffer + newbuffer);
	pe.file_header->NumberOfSections++;
	
	delete[]buffer;
	buffer = newbuffer;
	return TRUE;
}