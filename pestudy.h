#pragma once
#include<Windows.h>
#include<iostream>
#include<memory.h>
typedef struct PE {
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_FILE_HEADER file_header;
	PIMAGE_OPTIONAL_HEADER op_header;
	PIMAGE_SECTION_HEADER sectionheader;
	//PIMAGE_IMPORT_DESCRIPTOR importdescriptor;
};

BOOL Writeprocess(PCHAR filename,PVOID buffer,PE pe);//写入到文件中

BOOL RVAtoFA(PE pe, DWORD RVA, DWORD &FA);//虚拟偏移转文件偏移

BOOL FAtoRVA(PE pe, DWORD &RVA, DWORD FA);//文件偏移转虚拟偏移

BOOL Readprocess(PCHAR dest_process, PVOID & buffer);//读取应用的字节码，放在堆中(buffer)，后期需要free

BOOL CheckAndSet(PVOID buffer, PE &pe);//检查是否符合pe结构，如果不符合则返回0，否则将pe的各个指针指向正确的位置

BOOL PrintEverything(PE &pe);//打印所有的结构,打印成功返回true

BOOL PrintImport(PE pe);//打印导入表

BOOL PrintExport(PE pe);//打印导出表

BOOL AddSection(PE &pe,PVOID &buffer);//增加一个节