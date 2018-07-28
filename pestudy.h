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
/*
filename：要写入的文件路径
buffer:   包含程序信息的指针
pe:		  指向各个PE头关键位置
*/
BOOL RVAtoFA(PE pe, DWORD RVA, DWORD &FA);//虚拟偏移转文件偏移

BOOL FAtoRVA(PE pe, DWORD &RVA, DWORD FA);//文件偏移转虚拟偏移

BOOL Readprocess(PCHAR dest_process, PVOID & buffer);//读取应用的字节码，放在堆中(buffer)，后期需要free

BOOL CheckAndSet(PVOID buffer, PE &pe);//检查是否符合pe结构，如果不符合则返回0，否则将pe的各个指针指向正确的位置

BOOL PrintEverything(PE &pe);//打印所有的结构,打印成功返回true

BOOL PrintImport(PE pe);//打印导入表

BOOL PrintExport(PE pe);//打印导出表

BOOL AddSection(PE &pe,PVOID &buffer);//增加一个节

BOOL  AddCode(PE pe, PBYTE Code, DWORD codesize, DWORD extrodatasize);//在新增加的节中添加代码
/*
pe:指向pe结构的各个字段
Code:shellcode内容
codesize:shellcode的长度
extrodatasize:附加数据的长度，例如字符串等都附着在后面
*/

BOOL PrintRelocation(PE & pe);//打印重定位表
BOOL ExaToMem(PE &pe,PVOID &newbuffer);//将exe拉伸到内存中
/*
PE:获取PE结构
newbuffer:指向拉伸后的空间
*/