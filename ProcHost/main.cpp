#include <string>
#include <iostream>
#include <Windows.h>

int main() {
	std::string text = "CHANGE ME";
	while (true) {
		std::printf("TEXT: %s\n", text.c_str());
		Sleep(1000);
	}
	return 0;
}