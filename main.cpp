#include"pestudy.h"
using namespace std;
int main() {
	CHAR dest_process[] = "testfoo.exe";
	CHAR write_process[] = "testfoo1.exe";
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
	
	//PrintEverything(pe);//打印各个字段
	//DWORD RVA, FA;
	//PrintImport(pe);
	//PrintExport(pe);
	AddSection(pe,buffer);
	Writeprocess(write_process, buffer, pe);
	delete[]buffer;
	buffer = NULL;
	return 0;
}