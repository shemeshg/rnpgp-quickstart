#pragma once
#include <string>
#include <filesystem>
class RnpCoreParams
{
public:
    RnpCoreParams();
    bool CFG_KEYSTORE_DISABLED = false;
    std::string CFG_KR_PUB_PATH, CFG_KR_SEC_PATH, CFG_KEYSTOREFMT, CFG_KR_PUB_FORMAT,
        CFG_KR_SEC_FORMAT;
    std::filesystem::path  CFG_HOMEDIR{getHomeFolder()}; 

private:
    std::string getHomeFolder();
};
