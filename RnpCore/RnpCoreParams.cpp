#include "RnpCoreParams.h"
#include <rnp/rnp.h>

RnpCoreParams::RnpCoreParams()
{
    CFG_KR_PUB_FORMAT = RNP_KEYSTORE_GPG;
    CFG_KR_SEC_FORMAT = RNP_KEYSTORE_GPG;
}

std::string RnpCoreParams::getHomeFolder()
{
#ifdef WINDOWS
    std::string path = std::string(std::getenv("APPDATA")) + "\\gnupg";
    // use the path string as needed
    return path;
#else
    std::string path = std::string(std::getenv("HOME")) + "/.gnupg";
    return path;
#endif
}
