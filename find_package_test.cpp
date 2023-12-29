#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <string>
#include "file-utils.h"
#include <unistd.h>
#include <iostream>
#include "RnpCoreDefinitions.h"

class RnpCoreParams
{
public:
    bool CFG_KEYSTORE_DISABLED = false;
    std::string CFG_KR_PUB_PATH, CFG_KR_SEC_PATH,
        CFG_KEYSTOREFMT,
        CFG_KR_PUB_FORMAT{RNP_KEYSTORE_GPG},
        CFG_KR_SEC_FORMAT{RNP_KEYSTORE_GPG},
        CFG_HOMEDIR{getHomeFolder()};

private:
    std::string getHomeFolder()
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
};

class RnpCoreBal
{
public:
    RnpCoreBal()
    {
        if (rnp_cfg_set_ks_info())
        {
            std::cout << cfg.CFG_KR_PUB_PATH << "\n";
        } else {
            return;
        }
        // initialize FFI object
        if (rnp_ffi_create(&ffi, cfg.CFG_KR_PUB_FORMAT.c_str(), cfg.CFG_KR_SEC_FORMAT.c_str()) != RNP_SUCCESS)
        {
            return;
        }
        load_keyrings(true);        

    };

private:
    RnpCoreParams cfg{};
    rnp_ffi_t ffi = NULL;
    int result = 1;
    
    bool
    rnp_cfg_set_ks_info()
    {

        /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
         * considered as the final path */
        bool defhomedir = false;
        std::string homedir = cfg.CFG_HOMEDIR;
        if (homedir.empty())
        {
            homedir = rnp::path::HOME();
            defhomedir = true;
        }

        /* creating home dir if needed */
        if (defhomedir)
        {
            char *rnphome = NULL;
            if (rnp_get_default_homedir(&rnphome))
            {
                ERR_MSG("Failed to obtain default home directory.");
                return false;
            }
            homedir = rnphome;
            rnp_buffer_destroy(rnphome);
        }
        /* detecting key storage format */
        std::string ks_format = cfg.CFG_KEYSTOREFMT;
        if (ks_format.empty())
        {
            char *pub_format = NULL;
            char *sec_format = NULL;
            char *pubpath = NULL;
            char *secpath = NULL;
            rnp_detect_homedir_info(homedir.c_str(), &pub_format, &pubpath, &sec_format, &secpath);
            bool detected = pub_format && sec_format && pubpath && secpath;
            if (detected)
            {
                cfg.CFG_KR_PUB_FORMAT = pub_format;
                cfg.CFG_KR_SEC_FORMAT = sec_format;
                cfg.CFG_KR_PUB_PATH = pubpath;
                cfg.CFG_KR_SEC_PATH = secpath;
            }
            else
            {
                /* default to GPG */
                ks_format = RNP_KEYSTORE_GPG;
            }

            rnp_buffer_destroy(pub_format);
            rnp_buffer_destroy(sec_format);
            rnp_buffer_destroy(pubpath);
            rnp_buffer_destroy(secpath);
            if (detected)
            {
                return true;
            }
        }

        std::string pub_format = RNP_KEYSTORE_GPG;
        std::string sec_format = RNP_KEYSTORE_GPG;
        std::string pubpath;
        std::string secpath;

        if (ks_format == RNP_KEYSTORE_GPG)
        {
            pubpath = rnp::path::append(homedir, PUBRING_GPG);
            secpath = rnp::path::append(homedir, SECRING_GPG);
        }
        else if (ks_format == RNP_KEYSTORE_GPG21)
        {
            pubpath = rnp::path::append(homedir, PUBRING_KBX);
            secpath = rnp::path::append(homedir, SECRING_G10);
            pub_format = RNP_KEYSTORE_KBX;
            sec_format = RNP_KEYSTORE_G10;
        }
        else if (ks_format == RNP_KEYSTORE_KBX)
        {
            pubpath = rnp::path::append(homedir, PUBRING_KBX);
            secpath = rnp::path::append(homedir, SECRING_KBX);
            pub_format = RNP_KEYSTORE_KBX;
            sec_format = RNP_KEYSTORE_KBX;
        }
        else if (ks_format == RNP_KEYSTORE_G10)
        {
            pubpath = rnp::path::append(homedir, PUBRING_G10);
            secpath = rnp::path::append(homedir, SECRING_G10);
            pub_format = RNP_KEYSTORE_G10;
            sec_format = RNP_KEYSTORE_G10;
        }
        else
        {
            ERR_MSG("Unsupported keystore format: \"%s\"", ks_format.c_str());
            return false;
        }

        /* Check whether homedir is empty */
        if (rnp::path::empty(homedir))
        {
            ERR_MSG("Keyring directory '%s' is empty.\nUse \"rnpkeys\" command to generate a new "
                    "key or import existing keys from the file or GnuPG keyrings.",
                    homedir.c_str());
        }

        cfg.CFG_KR_PUB_PATH = pubpath;
        cfg.CFG_KR_SEC_PATH = secpath;
        cfg.CFG_KR_PUB_FORMAT = pub_format;
        return true;
    }

    bool load_keyring(bool secret)
    {
        const std::string &path = secret ? cfg.CFG_KR_SEC_PATH : cfg.CFG_KR_PUB_PATH;
        bool dir = secret && (cfg.CFG_KR_SEC_FORMAT == RNP_KEYSTORE_G10);
        if (!rnp::path::exists(path, dir))
        {
            return true;
        }

        rnp_input_t keyin = NULL;
        if (rnp_input_from_path(&keyin, path.c_str()))
        {
            ERR_MSG("Warning: failed to open keyring at path '%s' for reading.", path.c_str());
            return true;
        }

        const char *format = secret ? cfg.CFG_KR_SEC_FORMAT.c_str() : cfg.CFG_KR_PUB_FORMAT.c_str();
        uint32_t flags = secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS;

        rnp_result_t ret = rnp_load_keys(ffi, format, keyin, flags);
        if (ret)
        {
            ERR_MSG("Error: failed to load keyring from '%s'", path.c_str());
        }
        rnp_input_destroy(keyin);

        if (ret)
        {
            return false;
        }

        size_t keycount = 0;
        if (secret)
        {
            (void)rnp_get_secret_key_count(ffi, &keycount);
        }
        else
        {
            (void)rnp_get_public_key_count(ffi, &keycount);
        }
        if (!keycount)
        {
            ERR_MSG("Warning: no keys were loaded from the keyring '%s'.", path.c_str());
        }
        return true;
    }

    bool load_keyrings(bool loadsecret)
    {
        /* Read public keys */
        if (rnp_unload_keys(ffi, RNP_KEY_UNLOAD_PUBLIC))
        {
            ERR_MSG("failed to clear public keyring");
            return false;
        }

        if (!load_keyring(false))
        {
            return false;
        }

        /* Only read secret keys if we need to */
        if (loadsecret)
        {
            if (rnp_unload_keys(ffi, RNP_KEY_UNLOAD_SECRET))
            {
                ERR_MSG("failed to clear secret keyring");
                return false;
            }

            if (!load_keyring(true))
            {
                return false;
            }
        }

        return true;
    }
};

int main(int argc, char *argv[])
{
    printf("RNP version: %s\n", rnp_version_string());
    RnpCoreBal rbl{};


    return 0;
}
