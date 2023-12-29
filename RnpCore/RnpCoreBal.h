#pragma once


#include "RnpCoreParams.h"
#include "RnpKeys.h"
#include "RnpCoreInterface.h"
#include "rnpcpp.hpp"

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

#include <functional>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

class RnpCoreBal: public RnpCoreInterface 
{
public:
    ~RnpCoreBal();

    RnpCoreBal();

    void initPgpFactory() override {} 

    void decryptFileToString(const std::string &filePath,
                             std::string &decrypted,
                             std::vector<std::string> &decryptedSignedBy) override;

    void decryptFileToFile(const std::string &fromFilePath, const std::string &toFilePath) override;

    void encryptSignStringToFile(const std::string &inStr,
                                 const std::string &outFilePath,
                                 std::vector<std::string> encryptTo,
                                 bool doSign) override;

    void encryptSignFileToFile(const std::string &inFilePath,
                               const std::string &outFilePath,
                               std::vector<std::string> encryptTo,
                               bool doSign) override;

    void reEncryptFile(std::string pathFileToReEncrypt,
                       std::vector<std::string> encryptTo,
                       bool doSign) override;

    void setCtxSigners(std::vector<std::string> signedBy) override;

    static bool ffi_export_key(rnp_ffi_t ffi,
                               const char *uid,
                               bool secret,
                               const std::string &filePath);

    void exportPublicKey(const std::string &keyId, const std::string &filePath) override;

    void importPublicKey(const std::string &filePath, bool doTrust) override;

    // Not Implemented
    void trustPublicKey(std::string const &keyId) override;

    std::string getPrimaryKey(std::string searchKey) override;

    std::vector<RnpKeys> listKeys(const std::string pattern, bool secret_only) override;

    std::string getRnpVersionString() override;

    std::string runPasswordCallback(std::string s) override {
        return passwordCallback(s);
    }

    void setPasswordCallback(std::function<std::string(std::string s)> func) override {
        passwordCallback = func;
    }

private:
    RnpCoreParams cfg{};
    rnp_ffi_t ffi = NULL;
    int result = 1;
    std::string signer_fingerprint;
    bool isArmor = false;

    static bool example_pass_provider(rnp_ffi_t ffi,
                                      void *app_ctx,
                                      rnp_key_handle_t key,
                                      const char *pgp_context,
                                      char buf[],
                                      size_t buf_len);

    static bool import_keys(rnp_ffi_t ffi, const std::string &path, uint32_t flags);

    static bool import_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len, uint32_t flags);

    static bool key_matches_string(rnpffi::Key &key, const std::string &str);

#ifndef RNP_USE_STD_REGEX
    static std::string cli_rnp_unescape_for_regcomp(const std::string &src);
#endif

    static bool add_key_to_array(rnp_ffi_t ffi,
                                 std::vector<rnp_key_handle_t> &keys,
                                 rnp_key_handle_t key,
                                 int flags);

    static void clear_key_handles(std::vector<rnp_key_handle_t> &keys);

    static bool key_matches_flags(rnpffi::Key &key, int flags);

    bool keys_matching(std::vector<rnp_key_handle_t> &keys, const std::string &str, int flags);

    bool rnp_cfg_set_ks_info();

    bool load_keyring(bool secret);

    bool load_keyrings(bool loadsecret);

    std::function<std::string(std::string s)> passwordCallback = [&](std::string keyid)
    {
        std::cout << "******** " << keyid <<" PASSWORD **********\n";
        std::string pass;
        std::cin>>pass;
        return pass;
    };    
};
