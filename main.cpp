
#include <string>
#include <iostream>
#include <vector>

#include "RnpCoreInterface.h"
#include "RnpKeys.h"

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
void SetStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int main(int argc, char *argv[])
{
    auto rbl = getRnpCoreInterface();

    rbl->setPasswordCallback([&](std::string keyid)
                             {
        std::cout << "******** " << keyid <<" pass **********\n";
        std::string pass;
        SetStdinEcho(false);
        std::cin>>pass;
        SetStdinEcho(true);
        return pass; });

    std::cout << "RNP version: " << rbl->getRnpVersionString() << "\n";

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
