#pragma once

#include "RnpKeys.h"
#include <string>
#include <vector>
#include <iostream>
#include <functional>

class RnpCoreInterface
{
public:
    virtual ~RnpCoreInterface() {}
    virtual void decryptFileToString(std::string const &filePath,
                                     std::string &decrypted,
                                     std::vector<std::string> &decryptedSignedBy)
        = 0;

    virtual void encryptSignFileToFile(std::string const &inFilePath,
                                       std::string const &outFilePath,
                                       std::vector<std::string> encryptTo,
                                       bool doSign)
        = 0;

    virtual void encryptSignStringToFile(std::string const &inStr,
                                         std::string const &outFilePath,
                                         std::vector<std::string> encryptTo,
                                         bool doSign)
        = 0;

    virtual void decryptFileToFile(std::string const &fromFilePath, std::string const &toFilePath)
        = 0;

    virtual std::vector<RnpKeys> listKeys(const std::string pattern = "", bool secret_only = false)
        = 0;
    virtual void initPgpFactory() = 0;
    virtual void setCtxSigners(std::vector<std::string> signedBy) = 0;
    virtual void exportPublicKey(std::string const &keyId, std::string const &filePath) = 0;
    virtual void importPublicKey(std::string const &filePath, bool doTrust) = 0;
    virtual void trustPublicKey(std::string const &keyId) = 0;
    virtual void reEncryptFile(std::string pathFileToReEncrypt,
                               std::vector<std::string> encryptTo,
                               bool doSign)
        = 0;

    std::function<std::string(std::string s)> passwordCallback = [&](std::string keyid)
    {
        std::cout << "******** " << keyid <<" PASSWORD **********\n";
        std::string pass;
        std::cin>>pass;
        return pass;
    };

    virtual std::string getPrimaryKey(std::string key){
        return {};
    };
};

std::unique_ptr<RnpCoreInterface> getRnpCoreInterface();

