/**********************************************/
/**********************************************/
/***********                        ***********/
/***********	ytk2128@gmail.com	***********/
/***********                        ***********/
/**********************************************/
/**********************************************/

#include <iostream>
#include <string>
#include <vector>
#include "monitor.h"

using namespace std;

int main(int argc, char** argv) {
	if (argc < 3) {
		cout << "monitor.exe [pid] [dll name 1] [dll name 2] ... [dll name N]\n";
		return 1;
	}

	int pid = atoi(argv[1]);
	vector<string> dlls(&argv[2], &argv[argc]);

	Monitor montr(pid, dlls);
	if (montr.ready()) {
		montr.start();
		while (!threadExit);
		Sleep(2000);
	}
	else {
		cerr << "Failed to prepare for the target.\n";
		return 1;
	}
	
	return 0;
}