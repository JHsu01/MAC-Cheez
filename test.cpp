#include <hashlibpp.h>
#include <string>

int main() {
	//char* file_path = "~/Desktop/bug.png";
	hashwrapper* my_wrapper = new sha256wrapper();
	std::string hash = my_wrapper->getHashFromFile("LEC-08.mp4");
	printf("hash: %s\n", hash.c_str());
}
