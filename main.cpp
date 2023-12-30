
#include <string>
#include <iostream>
#include <vector>

#include "RnpCoreInterface.h"
#include "RnpKeys.h"

int main(int argc, char *argv[])
{
    auto rbl=getRnpCoreInterface();
    rbl->setPasswordCallback([&](std::string keyid)
    {
        std::cout << "******** " << keyid <<" pass **********\n";
        std::string pass;
        std::cin>>pass;
        return pass;
    }    );
    std::cout<<"RNP version: " << rbl->getRnpVersionString()<<"\n";
    for (auto &k : rbl->listKeys("", false))
    {
        std::cout << k.getKeyStr() << "\n";
    }

    /*
    const std::string filePath{"/Volumes/RAM_Disk_4G/tmp/file.gpg"};
    std::string decrypted;
    std::vector<std::string> decryptedSignedBy;
    rbl->decryptFileToString(filePath, decrypted, decryptedSignedBy);
    std::cout << "text is\n"
              << decrypted << "\n";
    */
    return 0;
}
