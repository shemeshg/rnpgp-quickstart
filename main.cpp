
#include <string>
#include <iostream>
#include <vector>

#include "RnpCoreInterface.h"
#include "RnpKeys.h"

int main(int argc, char *argv[])
{
    //printf("RNP version: %s\n", rnp_version_string());
    auto rbl=getRnpCoreInterface();
    for (auto &k : rbl->listKeys("", false))
    {
        std::cout << k.getKeyStr() << "\n";
    }

    const std::string filePath{"/Volumes/RAM_Disk_4G/tmp/file.gpg"};
    std::string decrypted;
    std::vector<std::string> decryptedSignedBy;
    rbl->decryptFileToString(filePath, decrypted, decryptedSignedBy);
    std::cout << "text is\n"
              << decrypted << "\n";
    return 0;
}
