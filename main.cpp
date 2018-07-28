#include"pestudy.h"
using namespace std;
int(*ff)();
int main(int argc,char * argv[]) {
	CHAR dest_process[] = "D:\\Program Files (x86)\\workspace\\PE_study\\PE_study\\123.EXE";
	//CHAR dest_process[] = "D:\\Program Files (x86)\\workspace\\PE_study\\PE_study\\PROCS.DLL";
	//dest_process = argv[1];
	//CHAR write_process[] = "LeetCode1.exe";
	PE pe;
	PVOID buffer = NULL;
	if (!Readprocess(dest_process, buffer)) {
		cout << "Open Failed!" << endl;
		//delete[]buffer;
		return 0;
	}
	
	if (!CheckAndSet(buffer, pe)) {
		cout << "不是有效的PE格式！" << endl;
		delete[]buffer;
		return 0;
	}
	
	PrintEverything(pe);//打印各个字段
	DWORD RVA, FA;
	RVA = 0x295DC;
	RVAtoFA(pe, RVA, FA);
	PrintImport(pe);
	PrintExport(pe);
	//AddSection(pe,buffer);

	//加载createdll.dll的硬编码
	//BYTE Code[] = {0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xFF,0x15,0xF4,0xF2,0x42,0x00,
		//0xe9,0x00,0x00,0x00,0x00};//shellcode，在程序运行前弹出一个messagebox


	//BYTE Code[] = { 
	//	//保存现场
	//	0x60,0x9c,
	//	//*******************
	//	//关键代码
	//	0xe8,0x00,0x00,0x00,0x00,0x58,//通过call 0和pop eax将当前的地址传入到eax中，执行后eax中的值指向0x58的位置
	//	0x05,0x15,0x00,0x00,0x00,//eax+相对位置，shellcode定了之后可以定
	//	0x50,//将eax压如堆栈
	//	0xb8,0x00,0x00,0x00,0x00,
	//	0xff,0xd0,//call eax调用loadlibrary,
	//	//*******************
	//	//恢复现场
	//	0x9d,0x61,

	//	0xe9,0x00,0x00,0x00,0x00, //这五个字节用于跳转到对应的位置

	//	//需要使用到的字符串
	//	'c','r','e','a','t','e','d','l','l','.','d','l','l','\0'//加载的dll名称
	//};
	//HMODULE a = GetModuleHandleA("kernel32.dll");
	//DWORD loadlibrary = (DWORD)GetProcAddress(a, "LoadLibraryA");
	//DWORD *p = (DWORD *)(Code + 15);
	//*p = loadlibrary;
	//DWORD extrodatasize = 14;//加载的dll名称长度
	//AddCode(pe, Code, sizeof Code, extrodatasize);
	//Writeprocess(write_process, buffer, pe);
	PrintRelocation(pe);
	void * newbuffer = NULL;
	ExaToMem(pe, newbuffer);
	
	ff = (int(*)())((PBYTE)newbuffer+pe.op_header->AddressOfEntryPoint);
	
	HMODULE hker = LoadLibrary(TEXT("Kernel32.dll"));
	DWORD add = (DWORD)GetProcAddress(hker, "GetVersion");
	/*HANDLE h1=GetModuleHandle(0);
	PE nowpe;
	CheckAndSet((PVOID)h1, nowpe);
	DWORD lpflOldProtect;
	VirtualProtect((PVOID)h1, nowpe.op_header->SizeOfImage + 0x20, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	DWORD tempaddr = nowpe.op_header->DataDirectory[13].VirtualAddress;
	nowpe.op_header->DataDirectory[13].VirtualAddress = pe.op_header->DataDirectory[13].VirtualAddress;*/
	ff();
	//nowpe.op_header->DataDirectory[13].VirtualAddress = tempaddr;
	delete[]newbuffer;
	newbuffer = NULL;
	delete[]buffer;
	buffer = NULL;
	//getchar();
	return 0;
}