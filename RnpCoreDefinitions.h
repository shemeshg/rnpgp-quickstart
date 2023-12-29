#pragma once

/* TODO: we should decide what to do with functions/constants/defines below */
#define RNP_FP_V4_SIZE 20
#if defined(ENABLE_CRYPTO_REFRESH)
#define RNP_PGP_VER_6 6
#define RNP_FP_V6_SIZE 32
#endif
#define RNP_KEYID_SIZE 8
#define RNP_GRIP_SIZE 20

#define ERR_MSG(...)                          \
    do                                        \
    {                                         \
        (void)fprintf((stderr), __VA_ARGS__); \
        (void)fprintf((stderr), "\n");        \
    } while (0)

#define EXT_ASC (".asc")
#define EXT_SIG (".sig")
#define EXT_PGP (".pgp")
#define EXT_GPG (".gpg")

#define SUBDIRECTORY_GNUPG ".gnupg"
#define SUBDIRECTORY_RNP ".rnp"
#define PUBRING_KBX "pubring.kbx"
#define SECRING_KBX "secring.kbx"
#define PUBRING_GPG "pubring.gpg"
#define SECRING_GPG "secring.gpg"
#define PUBRING_G10 "public-keys-v1.d"
#define SECRING_G10 "private-keys-v1.d"

typedef enum cli_search_flags_t {
    CLI_SEARCH_SECRET = 1 << 0,     /* search secret keys only */
    CLI_SEARCH_SUBKEYS = 1 << 1,    /* add subkeys as well */
    CLI_SEARCH_FIRST_ONLY = 1 << 2, /* return only first key matching */
    CLI_SEARCH_SUBKEYS_AFTER =
      (1 << 3) | CLI_SEARCH_SUBKEYS, /* put subkeys after the primary key */
    CLI_SEARCH_DEFAULT = 1 << 4      /* add default key if nothing found */
} cli_search_flags_t;