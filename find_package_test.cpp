#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <string>
#include "file-utils.h"
#include <unistd.h>
#include <iostream>
#include "RnpCoreDefinitions.h"
#include "RnpKeys.h"
#include <vector>
#include "rnpcpp.hpp"
#include "str-utils.h"
#ifndef RNP_USE_STD_REGEX
#include <regex.h>
#else
#include <regex>
#endif

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
    ~RnpCoreBal()
    {
        rnp_ffi_destroy(ffi);
    }

    RnpCoreBal()
    {
        if (!rnp_cfg_set_ks_info())
        {
            return;
        }
        // initialize FFI object
        if (rnp_ffi_create(&ffi, cfg.CFG_KR_PUB_FORMAT.c_str(), cfg.CFG_KR_SEC_FORMAT.c_str()) != RNP_SUCCESS)
        {
            return;
        }
        load_keyrings(true);
    };

    std::vector<RnpKeys> listKeys(const std::string pattern, bool secret_only)
    {
        std::vector<RnpKeys> retKeys = {};

        std::vector<rnp_key_handle_t> keys;

        int flags = secret_only ? CLI_SEARCH_SECRET : 0;
        if (!keys_matching(keys, pattern, flags))
        {
            throw std::runtime_error("Key(s) not found.\n");
        }

        for (auto key : keys)
        {
            char *keyfp = NULL;
            char *uid_str = NULL;
            char *keyid = NULL;
            (void)rnp_key_get_uid_at(key, 0, &uid_str);
            (void)rnp_key_get_fprint(key, &keyfp);
            (void)rnp_key_get_keyid(key, &keyid);

            RnpKeys gk;
            std::string nameAndEmail = uid_str;
            size_t pos_email_start = nameAndEmail.find_first_of('<');
            size_t pos_email_end = nameAndEmail.find_first_of('>');
            gk.name = nameAndEmail.substr(0, pos_email_start - 1);
            gk.email = nameAndEmail.substr(pos_email_start + 1, pos_email_end - pos_email_start - 1);
            gk.keyid = keyid;
            gk.foundUsingPattern = pattern;
            gk.can_encrypt = secret_only;
            gk.validity = 0;
            retKeys.push_back(gk);

            rnp_buffer_destroy(uid_str);
            rnp_buffer_destroy(keyfp);
            rnp_buffer_destroy(keyid);
        }

        return retKeys;
    }

private:
    RnpCoreParams cfg{};
    rnp_ffi_t ffi = NULL;
    int result = 1;

    static bool
    key_matches_string(rnpffi::Key &key, const std::string &str)
    {
        if (str.empty())
        {
            return true;
        }
        if (rnp::is_hex(str) && (str.length() >= RNP_KEYID_SIZE))
        {
            std::string hexstr = rnp::strip_hex(str);
            size_t len = hexstr.length();

            /* check whether it's key id */
            if ((len == RNP_KEYID_SIZE * 2) || (len == RNP_KEYID_SIZE))
            {
                auto keyid = key.keyid();
                if (keyid.size() < len)
                {
                    return false;
                }
                if (!strncasecmp(hexstr.c_str(), keyid.c_str() + keyid.size() - len, len))
                {
                    return true;
                }
            }

            /* check fingerprint */
            auto keyfp = key.fprint();
            if ((len == keyfp.size()) && !strncasecmp(hexstr.c_str(), keyfp.c_str(), len))
            {
                return true;
            }

            /* check grip */
            auto grip = key.grip();
            if (len == grip.size())
            {
                if (!strncasecmp(hexstr.c_str(), grip.c_str(), len))
                {
                    return true;
                }
            }
            /* let then search for hex userid */
        }

        /* no need to check for userid over the subkey */
        if (key.is_sub())
        {
            return false;
        }
        auto uid_count = key.uid_count();
        if (!uid_count)
        {
            return false;
        }

#ifndef RNP_USE_STD_REGEX
        regex_t r = {};
        /* match on full name or email address as a NOSUB, ICASE regexp */
        if (regcomp(&r, cli_rnp_unescape_for_regcomp(str).c_str(), REG_EXTENDED | REG_ICASE) !=
            0)
        {
            return false;
        }
#else
        std::regex re;
        try
        {
            re.assign(str, std::regex_constants::ECMAScript | std::regex_constants::icase);
        }
        catch (const std::exception &e)
        {
            ERR_MSG("Invalid regular expression : %s, error %s.", str.c_str(), e.what());
            return false;
        }
#endif

        bool matches = false;
        for (size_t idx = 0; idx < uid_count; idx++)
        {
            auto uid = key.uid_at(idx);
#ifndef RNP_USE_STD_REGEX
            if (regexec(&r, uid.c_str(), 0, NULL, 0) == 0)
            {
                matches = true;
                break;
            }
#else
            if (std::regex_search(uid, re))
            {
                matches = true;
                break;
            }
#endif
        }
#ifndef RNP_USE_STD_REGEX
        regfree(&r);
#endif
        return matches;
    }

#ifndef RNP_USE_STD_REGEX
    static std::string
    cli_rnp_unescape_for_regcomp(const std::string &src)
    {
        std::string result;
        result.reserve(src.length());
        regex_t r = {};
        regmatch_t matches[1];
        if (regcomp(&r, "\\\\x[0-9a-f]([0-9a-f])?", REG_EXTENDED | REG_ICASE) != 0)
            return src;

        int offset = 0;
        while (regexec(&r, src.c_str() + offset, 1, matches, 0) == 0)
        {
            result.append(src, offset, matches[0].rm_so);
            int hexoff = matches[0].rm_so + 2;
            std::string hex;
            hex.push_back(src[offset + hexoff]);
            if (hexoff + 1 < matches[0].rm_eo)
            {
                hex.push_back(src[offset + hexoff + 1]);
            }
            char decoded = stoi(hex, 0, 16);
            if ((decoded >= 0x7B && decoded <= 0x7D) || (decoded >= 0x24 && decoded <= 0x2E) ||
                decoded == 0x5C || decoded == 0x5E)
            {
                result.push_back('\\');
                result.push_back(decoded);
            }
            else if ((decoded == '[' || decoded == ']') &&
                     /* not enclosed in [] */ (result.empty() || result.back() != '['))
            {
                result.push_back('[');
                result.push_back(decoded);
                result.push_back(']');
            }
            else
            {
                result.push_back(decoded);
            }
            offset += matches[0].rm_eo;
        }

        result.append(src.begin() + offset, src.end());

        return result;
    }
#endif


static bool
add_key_to_array(rnp_ffi_t                      ffi,
                 std::vector<rnp_key_handle_t> &keys,
                 rnp_key_handle_t               key,
                 int                            flags)
{
    bool subkey = false;
    bool subkeys = (flags & CLI_SEARCH_SUBKEYS_AFTER) == CLI_SEARCH_SUBKEYS_AFTER;
    if (rnp_key_is_sub(key, &subkey)) {
        return false;
    }

    try {
        keys.push_back(key);
    } catch (const std::exception &e) {
        ERR_MSG("%s", e.what());
        return false;
    }
    if (!subkeys || subkey) {
        return true;
    }

    std::vector<rnp_key_handle_t> subs;
    size_t                        sub_count = 0;
    if (rnp_key_get_subkey_count(key, &sub_count)) {
        goto error;
    }

    try {
        for (size_t i = 0; i < sub_count; i++) {
            rnp_key_handle_t sub_handle = NULL;
            if (rnp_key_get_subkey_at(key, i, &sub_handle)) {
                goto error;
            }
            subs.push_back(sub_handle);
        }
        std::move(subs.begin(), subs.end(), std::back_inserter(keys));
    } catch (const std::exception &e) {
        ERR_MSG("%s", e.what());
        goto error;
    }
    return true;
error:
    keys.pop_back();
    clear_key_handles(subs);
    return false;
}

static void
clear_key_handles(std::vector<rnp_key_handle_t> &keys)
{
    for (auto handle : keys) {
        rnp_key_handle_destroy(handle);
    }
    keys.clear();
}

    static bool
    key_matches_flags(rnpffi::Key &key, int flags)
    {
        /* check whether secret key search is requested */
        if ((flags & CLI_SEARCH_SECRET) && !key.secret())
        {
            return false;
        }
        /* check whether no subkeys allowed */
        if (!key.is_sub())
        {
            return true;
        }
        if (!(flags & CLI_SEARCH_SUBKEYS))
        {
            return false;
        }
        /* check whether subkeys should be put after primary (if it is available) */
        if ((flags & CLI_SEARCH_SUBKEYS_AFTER) != CLI_SEARCH_SUBKEYS_AFTER)
        {
            return true;
        }

        return key.primary_grip().empty();
    }

    bool
    keys_matching(std::vector<rnp_key_handle_t> &keys,
                 const std::string &str,
                 int flags)
    {
        rnpffi::FFI ffiobj(ffi, false);

        /* iterate through the keys */
        auto it = ffiobj.iterator_create("fingerprint");
        if (!it)
        {
            return false;
        }

        std::string fp;
        while (it->next(fp))
        {
            auto key = ffiobj.locate_key("fingerprint", fp);
            if (!key)
            {
                continue;
            }
            if (!key_matches_flags(*key, flags) || !key_matches_string(*key, str))
            {
                continue;
            }
            if (!add_key_to_array(ffi, keys, key->handle(), flags))
            {
                return false;
            }
            key->release();
            if (flags & CLI_SEARCH_FIRST_ONLY)
            {
                return true;
            }
        }
        return !keys.empty();
    }

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
    for (auto &k :rbl.listKeys("",false)){
        std::cout<<k.getKeyStr()<<"\n";
    }
    return 0;
}
