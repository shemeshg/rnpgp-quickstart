#include "RnpCoreDefinitions.h"
#include "str-utils.h"
#include <filesystem>

#include <map>

#include "RnpCoreBal.h"

RnpCoreBal::~RnpCoreBal()
{
    rnp_ffi_destroy(ffi);
}

RnpCoreBal::RnpCoreBal()
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
    rnp_ffi_set_pass_provider(ffi, example_pass_provider, this);
}

void RnpCoreBal::decryptFileToString(const std::string &filePath,
                                     std::string &decrypted,
                                     std::vector<std::string> &decryptedSignedBy)
{
    rnp_input_t input = NULL;
    rnp_output_t output = NULL;
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    if (rnp_input_from_path(&input, filePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create input object\n");
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create output object\n");
    }

    rnp_op_verify_t verify = NULL;

    if (rnp_op_verify_create(&verify, ffi, input, output) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create verification context\n");
    }
    rnp_op_verify_execute(verify);

    size_t sigcount = 0;
    if (rnp_op_verify_get_signature_count(verify, &sigcount) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to get signature count\n");
    }
    // get the decrypted message from the output structure
    if (rnp_output_memory_get_buf(output, &buf, &buf_len, false) != RNP_SUCCESS)
    {
        throw std::runtime_error("LoginReq:");
    }
    decrypted = std::string(buf, buf + buf_len);
    for (size_t i = 0; i < sigcount; i++)
    {
        rnp_op_verify_signature_t sig = NULL;
        rnp_result_t sigstatus = RNP_SUCCESS;
        rnp_key_handle_t key = NULL;
        char *keyid = NULL;

        if (rnp_op_verify_get_signature_at(verify, i, &sig) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to get signature " + std::to_string(i) + "\n");
        }

        if (rnp_op_verify_signature_get_key(sig, &key) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to get signature's " + std::to_string(i) + " key\n");
        }

        if (rnp_key_get_keyid(key, &keyid) != RNP_SUCCESS)
        {
            rnp_key_handle_destroy(key);
            throw std::runtime_error("failed to get key id " + std::to_string(i) + "\n");
        }

        sigstatus = rnp_op_verify_signature_get_status(sig);
        decryptedSignedBy.push_back(keyid);
        rnp_buffer_destroy(keyid);
        rnp_key_handle_destroy(key);
    }

    rnp_input_destroy(input);
    rnp_output_destroy(output);
}

void RnpCoreBal::decryptFileToFile(const std::string &fromFilePath, const std::string &toFilePath)
{
    rnp_input_t input = NULL;
    rnp_output_t output = NULL;
    uint8_t *buf = NULL;
    size_t buf_len = 0;
    if (rnp_input_from_path(&input, fromFilePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create input object\n");
    }

    if (rnp_output_to_path(&output, toFilePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create output object\n");
    }

    if (rnp_decrypt(ffi, input, output) != RNP_SUCCESS)
    {
        throw std::runtime_error("LoginReq:");
    }

    rnp_input_destroy(input);
    rnp_output_destroy(output);
}

void RnpCoreBal::encryptSignStringToFile(const std::string &inStr,
                                         const std::string &outFilePath,
                                         std::vector<std::string> encryptTo,
                                         bool doSign)
{
    rnp_input_t input = NULL;
    rnp_output_t output = NULL;
    const char *message = inStr.c_str();

    /* create memory input and file output objects for the message and encrypted message */
    if (rnp_input_from_memory(&input, (uint8_t *)message, strlen(message), false) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create input object\n");
    }

    if (rnp_output_to_path(&output, outFilePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create output object\n");
    }

    /* create encryption operation */
    rnp_op_encrypt_t encrypt = NULL;
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create encrypt operation\n");
    }

    /* setup encryption parameters */
    rnp_op_encrypt_set_armor(encrypt, isArmor);
    rnp_op_encrypt_set_file_name(encrypt, outFilePath.c_str());
    rnp_op_encrypt_set_file_mtime(encrypt, (uint32_t)time(NULL));
    // rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    for (auto &eTo : encryptTo)
    {
        rnp_key_handle_t key = NULL;
        if (rnp_locate_key(ffi, "keyid", eTo.c_str(), &key) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to locate recipient key rsa@key.\n");
        }

        if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to add recipient\n");
        }
        rnp_key_handle_destroy(key);
    }

    std::vector<rnp_key_handle_t> signkeys;
    if (doSign && !signer_fingerprint.empty())
    {
        int flags = CLI_SEARCH_SECRET | CLI_SEARCH_DEFAULT | CLI_SEARCH_SUBKEYS | CLI_SEARCH_FIRST_ONLY;
        if (!keys_matching(signkeys, signer_fingerprint.c_str(), flags))
        {
            throw std::runtime_error("Key(s) not found.\n");
        }
        for (rnp_key_handle_t key : signkeys)
        {
            if (rnp_op_encrypt_add_signature(encrypt, key, NULL))
            {
                throw std::runtime_error("Failed to add signature");
            }
        }
    }

    /* execute encryption operation */
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS)
    {
        throw std::runtime_error("encryption failed\n");
    }

    clear_key_handles(signkeys);
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
}

void RnpCoreBal::encryptSignFileToFile(const std::string &inFilePath,
                                       const std::string &outFilePath,
                                       std::vector<std::string> encryptTo,
                                       bool doSign)
{
    rnp_input_t input = NULL;
    rnp_output_t output = NULL;

    if (rnp_input_from_path(&input, inFilePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create input object\n");
    }

    if (rnp_output_to_path(&output, outFilePath.c_str()) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create output object\n");
    }

    /* create encryption operation */
    rnp_op_encrypt_t encrypt = NULL;
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS)
    {
        throw std::runtime_error("failed to create encrypt operation\n");
    }

    /* setup encryption parameters */
    rnp_op_encrypt_set_armor(encrypt, isArmor);
    rnp_op_encrypt_set_file_name(encrypt, outFilePath.c_str());
    rnp_op_encrypt_set_file_mtime(encrypt, (uint32_t)time(NULL));
    // rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    for (auto &eTo : encryptTo)
    {
        rnp_key_handle_t key = NULL;
        if (rnp_locate_key(ffi, "keyid", eTo.c_str(), &key) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to locate recipient key rsa@key.\n");
        }

        if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS)
        {
            throw std::runtime_error("failed to add recipient\n");
        }
        rnp_key_handle_destroy(key);
    }

    if (doSign)
    {
        rnp_key_handle_t key = NULL;
        if (!signer_fingerprint.empty())
        {
            if (rnp_locate_key(ffi, "keyid", signer_fingerprint.c_str(), &key) != RNP_SUCCESS)
            {
                throw std::runtime_error("failed to locate recipient key rsa@key.\n");
            }
        }
        rnp_op_encrypt_add_signature(encrypt, key, NULL);
        rnp_key_handle_destroy(key);
    }

    /* execute encryption operation */
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS)
    {
        throw std::runtime_error("encryption failed\n");
    }

    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
}

void RnpCoreBal::reEncryptFile(std::string pathFileToReEncrypt,
                               std::vector<std::string> encryptTo,
                               bool doSign)
{
    std::string backupFile = pathFileToReEncrypt + "backup";
    std::string tempDecrypted = pathFileToReEncrypt + "decrypted";
    try
    {
        std::filesystem::rename(pathFileToReEncrypt, backupFile);

        std::vector<std::string> decryptedSignedBy{};
        decryptFileToFile(backupFile, tempDecrypted);

        encryptSignFileToFile(tempDecrypted, pathFileToReEncrypt, encryptTo, doSign);

        std::filesystem::remove(backupFile);
        std::filesystem::remove(tempDecrypted);
    }
    catch (...)
    {
        std::filesystem::rename(backupFile, pathFileToReEncrypt);
        std::filesystem::remove(tempDecrypted);
        throw;
    }
}

void RnpCoreBal::setCtxSigners(std::vector<std::string> signedBy)
{
    if (signedBy.size() > 0)
    {
        signer_fingerprint = signedBy[0];
    }
}

bool RnpCoreBal::ffi_export_key(rnp_ffi_t ffi,
                                const char *uid,
                                bool secret,
                                const std::string &filePath)
{
    rnp_output_t keyfile = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    char *keyid = NULL;
    bool result = false;

    /* you may search for the key via userid, keyid, fingerprint, grip */
    if (rnp_locate_key(ffi, "keyid", uid, &key) != RNP_SUCCESS)
    {
        return false;
    }

    if (!key)
    {
        return false;
    }

    /* get key's id and build filename */
    if (rnp_key_get_keyid(key, &keyid) != RNP_SUCCESS)
    {
        goto finish;
    }
    rnp_buffer_destroy(keyid);

    /* create file output structure */
    if (rnp_output_to_path(&keyfile, filePath.c_str()) != RNP_SUCCESS)
    {
        goto finish;
    }

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keyfile, flags) != RNP_SUCCESS)
    {
        goto finish;
    }

    result = true;
finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keyfile);
    return result;
}

void RnpCoreBal::exportPublicKey(const std::string &keyId, const std::string &filePath)
{
    ffi_export_key(ffi, keyId.c_str(), false, filePath);
}

void RnpCoreBal::importPublicKey(const std::string &filePath, bool doTrust)
{
    bool isSccussfull = import_keys(ffi, filePath, RNP_LOAD_SAVE_PUBLIC_KEYS);
    if (!isSccussfull)
    {
        throw std::runtime_error("Could not import key");
    }
}

void RnpCoreBal::trustPublicKey(const std::string &keyId) {}

std::string RnpCoreBal::getPrimaryKey(std::string searchKey)
{
    static std::map<std::string, std::string> cashPrimaryKey;

    std::map<std::string, std::string>::iterator it;

    if (cashPrimaryKey.count(searchKey))
    {
        return cashPrimaryKey[searchKey];
    }

    std::vector<std::string> retKeys = {};

    std::vector<rnp_key_handle_t> keys;

    int flags = true ? CLI_SEARCH_SECRET : 0;
    if (!keys_matching(keys, "", CLI_SEARCH_SUBKEYS_AFTER))
    {
        throw std::runtime_error("Key(s) not found.\n");
    }

    std::vector<std::string> ret{};
    bool found = false;
    for (auto key : keys)
    {
        char *keyid = NULL;
        (void)rnp_key_get_keyid(key, &keyid);

        bool isPrimary = false;
        rnp_key_is_primary(key, &isPrimary);
        if (keyid == searchKey)
        {
            found = true;
        }
        if (isPrimary)
        {
            ret = {keyid};
        }
        else
        {
            ret.push_back(keyid);
        }
        if (found)
        {
            cashPrimaryKey[searchKey] = ret.at(0);
            return ret.at(0);
        }

        rnp_buffer_destroy(keyid);
    }
    return searchKey;
}

std::vector<RnpKeys> RnpCoreBal::listKeys(const std::string pattern, bool secret_only)
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

bool RnpCoreBal::example_pass_provider(rnp_ffi_t ffi,
                                       void *app_ctx,
                                       rnp_key_handle_t key,
                                       const char *pgp_context,
                                       char buf[],
                                       size_t buf_len)
{
    // GpgFactoryInterface *libGpgFactoryRnp = static_cast<GpgFactoryInterface *>(app_ctx);
    RnpCoreInterface *libGpgFactoryRnp = static_cast<RnpCoreInterface *>(app_ctx);
    char *keyid = NULL;
    rnp_key_get_keyid(key, &keyid);
    std::string keyidStr{keyid};
    keyidStr = libGpgFactoryRnp->getPrimaryKey(keyidStr);

    std::string pass = libGpgFactoryRnp->runPasswordCallback(keyidStr);

    rnp_buffer_destroy(keyid);

    strncpy(buf, pass.c_str(), buf_len);
    return true;
}

bool RnpCoreBal::import_keys(rnp_ffi_t ffi, const std::string &path, uint32_t flags)
{
    rnp_input_t input = NULL;
    if (rnp_input_from_path(&input, path.c_str()))
    {
        return false;
    }
    bool res = !rnp_import_keys(ffi, input, flags, NULL);
    rnp_input_destroy(input);
    return res;
}

bool RnpCoreBal::import_keys(rnp_ffi_t ffi, const uint8_t *data, size_t len, uint32_t flags)
{
    rnp_input_t input = NULL;
    if (rnp_input_from_memory(&input, data, len, false))
    {
        return false;
    }
    bool res = !rnp_import_keys(ffi, input, flags, NULL);
    rnp_input_destroy(input);
    return res;
}

bool RnpCoreBal::add_key_to_array(rnp_ffi_t ffi,
                                  std::vector<rnp_key_handle_t> &keys,
                                  rnp_key_handle_t key,
                                  int flags)
{
    bool subkey = false;
    bool subkeys = (flags & CLI_SEARCH_SUBKEYS_AFTER) == CLI_SEARCH_SUBKEYS_AFTER;
    if (rnp_key_is_sub(key, &subkey))
    {
        return false;
    }

    try
    {
        keys.push_back(key);
    }
    catch (const std::exception &e)
    {
        ERR_MSG("%s", e.what());
        return false;
    }
    if (!subkeys || subkey)
    {
        return true;
    }

    std::vector<rnp_key_handle_t> subs;
    size_t sub_count = 0;
    if (rnp_key_get_subkey_count(key, &sub_count))
    {
        goto error;
    }

    try
    {
        for (size_t i = 0; i < sub_count; i++)
        {
            rnp_key_handle_t sub_handle = NULL;
            if (rnp_key_get_subkey_at(key, i, &sub_handle))
            {
                goto error;
            }
            subs.push_back(sub_handle);
        }
        std::move(subs.begin(), subs.end(), std::back_inserter(keys));
    }
    catch (const std::exception &e)
    {
        ERR_MSG("%s", e.what());
        goto error;
    }
    return true;
error:
    keys.pop_back();
    clear_key_handles(subs);
    return false;
}

void RnpCoreBal::clear_key_handles(std::vector<rnp_key_handle_t> &keys)
{
    for (auto handle : keys)
    {
        rnp_key_handle_destroy(handle);
    }
    keys.clear();
}

bool RnpCoreBal::key_matches_flags(rnpffi::Key &key, int flags)
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

bool RnpCoreBal::keys_matching(std::vector<rnp_key_handle_t> &keys,
                               const std::string &str,
                               int flags)
{
    // TODO **********************
    return keys_matching(keys,
                         flags);
}

bool RnpCoreBal::keys_matching(std::vector<rnp_key_handle_t> &keys,
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
        if (!key_matches_flags(*key, flags))
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

bool RnpCoreBal::rnp_cfg_set_ks_info()
{
    /* getting path to keyrings. If it is specified by user in 'homedir' param then it is
     * considered as the final path */
    bool defhomedir = false;
    std::filesystem::path homedir = cfg.CFG_HOMEDIR;

    /* detecting key storage format */
    std::string ks_format = cfg.CFG_KEYSTOREFMT;
    if (ks_format.empty())
    {
        char *pub_format = NULL;
        char *sec_format = NULL;
        char *pubpath = NULL;
        char *secpath = NULL;
        rnp_detect_homedir_info(homedir.generic_u8string().c_str(), &pub_format, &pubpath, &sec_format, &secpath);
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
        pubpath = (homedir/ PUBRING_GPG).generic_u8string();
        secpath = (homedir / SECRING_GPG).generic_u8string();
    }
    else if (ks_format == RNP_KEYSTORE_GPG21)
    {
        pubpath = (homedir / PUBRING_KBX).generic_u8string();
        secpath = (homedir / SECRING_G10).generic_u8string();
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_G10;
    }
    else if (ks_format == RNP_KEYSTORE_KBX)
    {
        pubpath = (homedir / PUBRING_KBX).generic_u8string();
        secpath = (homedir / SECRING_KBX).generic_u8string();
        pub_format = RNP_KEYSTORE_KBX;
        sec_format = RNP_KEYSTORE_KBX;
    }
    else if (ks_format == RNP_KEYSTORE_G10)
    {
        pubpath = (homedir/ PUBRING_G10).generic_u8string();
        secpath = (homedir/ SECRING_G10).generic_u8string();
        pub_format = RNP_KEYSTORE_G10;
        sec_format = RNP_KEYSTORE_G10;
    }
    else
    {
        ERR_MSG("Unsupported keystore format: \"%s\"", ks_format.c_str());
        return false;
    }

    /* Check whether homedir is empty */
    if (std::filesystem::is_empty(homedir))
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

bool RnpCoreBal::load_keyring(bool secret)
{
    const std::string &path = secret ? cfg.CFG_KR_SEC_PATH : cfg.CFG_KR_PUB_PATH;
    bool dir = secret && (cfg.CFG_KR_SEC_FORMAT == RNP_KEYSTORE_G10);

    if (!std::filesystem::exists(path) && std::filesystem::is_directory(path) != dir)
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

bool RnpCoreBal::load_keyrings(bool loadsecret)
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

std::string RnpCoreBal::getRnpVersionString()
{
    return rnp_version_string();
}