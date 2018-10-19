/*
 * detsign
 * Copyright (C) 2018 Simon Reiser
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 */

#undef NDEBUG

#if defined(_WIN32) || defined(WIN32)
#define OS_WIN32
#define VC_EXTRALEAN 1
#define WIN32_LEAN_AND_MEAN 1
#else
#define OS_UNIX 1
#endif

#include <sodium.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef OS_WIN32
#include <windows.h>
#include <conio.h>
#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
static inline void *
check_void_ptr_(void *x)
{
    return x;
}
#define VOIDPTR_CAST(T, ex) ((T) check_void_ptr_(ex))
#endif
#else
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

#ifndef VOIDPTR_CAST
#define VOIDPTR_CAST(T, ex) (ex)
#endif

#define PUB_FILE_EXT ".detsign.pub"
#define SEC_FILE_EXT ".detsign.sec"
#define SIG_FILE_EXT ".detsign.sig"

static const char *USAGE_STR =
  "Usage: detsign COMMAND [ARGS]...\n"
  "\n"
  "Options: \n"
  "  -p PUB        Path to public key, required file "
  "extension: " PUB_FILE_EXT "\n"
  "  -s SEC        Path to secret key, required file "
  "extension: " SEC_FILE_EXT "\n"
  "  -d SIG        Path to signature file, required file "
  "extension: " SIG_FILE_EXT "\n"
  "  -i SUBKEYID   Specify the subkeyid (a 64 bit unsigned integer),\n"
  "                hence many keypairs can be derived from the same "
  "passphrase,\n"
  "                default is 0.\n"
  "  -v            Enable more verbose output\n"
  "\n"
  "Commands:\n"
  "  gen -p PUB [-s SEC] [-i SUBKEYID]\n"
  "    Generate a signing keypair and save to disk.\n"
  "    If argument SEC is not set, don't save the secret key.\n"
  "\n"
  "  gen-sign [-p PUB] [-d SIG] [-i SUBKEYID] FILE\n"
  "    Generate the keypair on the fly using a passphrase and sign FILE.\n"
  "    If argument SIG is not set, save to FILE" SIG_FILE_EXT ".\n"
  "    If argument PUB is set, verify that it matches the generated one.\n"
  "\n"
  "  sign -s SEC [-d SIG] [FILE]\n"
  "    Sign FILE and save signature to SIG.\n"
  "    If argument SIG is not set, save to FILE" SIG_FILE_EXT ".\n"
  "    If argument FILE is not set, read data from stdin, in which case\n"
  "    argument SIG has to be given.\n"
  "\n"
  "  verify -p PUB [-d SIG] [FILE]\n"
  "    Verify a signature.\n"
  "    If argument SIG is not set, use FILE" SIG_FILE_EXT "\n"
  "    If argument FILE is not set, read data from stdin, in which case\n"
  "    argument SIG has to be given.\n"
  "\n"
  "  regen-pub -s SEC -p PUB\n"
  "    Recreate the pulickey PUB from secret key SEC\n";

#define BASE64_IGNORE_CHARS " \t\r\n"

#define BASE64_VARIANT sodium_base64_VARIANT_URLSAFE

typedef struct
{
    unsigned char data[crypto_sign_SECRETKEYBYTES];
} SecretKey;

typedef struct
{
    unsigned char data[crypto_sign_PUBLICKEYBYTES];
} PublicKey;

typedef struct
{
    unsigned char data[crypto_sign_BYTES];
} Signature;

typedef enum
{
    MODE_INVALID = 0,
    MODE_GEN,
    MODE_GEN_AND_SIGN,
    MODE_SIGN,
    MODE_VERIFY,
    MODE_REGEN_PUB
} ProgramMode;

typedef struct
{
    ProgramMode mode;
    int verbose;
    int has_subkeyid;
    uint64_t subkeyid;
    const char *pkfile;
    const char *skfile;
    const char *sigfile;
} ProgramArgs;

#ifdef OS_WIN32
typedef struct
{
    HANDLE stdinh;
    DWORD mode;
} TermState;
#else
typedef struct
{
    struct termios old;
    int reset_old;
} TermState;
#endif

static int
term_disable_echo(TermState *term, int *is_term)
{
    assert(is_term && "is_term cannot be NULL");
    *is_term = 0;
#ifdef OS_WIN32
    term->stdinh = INVALID_HANDLE_VALUE;
    HANDLE stdinh = GetStdHandle(STD_INPUT_HANDLE);
    if (stdinh == INVALID_HANDLE_VALUE)
        return -1;
    if (!GetConsoleMode(stdinh, &term->mode))
        return 0;
    *is_term = 1;
    DWORD newmode = term->mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    if (!SetConsoleMode(stdinh, newmode))
        return -1;
    term->stdinh = stdinh;
    return 0;
#else
    term->reset_old = 0;
    if (tcgetattr(STDIN_FILENO, &term->old) == -1)
        return 0;
    *is_term = 1;
    struct termios newterm = term->old;
    newterm.c_lflag = newterm.c_lflag & ~(ECHO | ICANON);
    newterm.c_cc[VMIN] = 1;
    newterm.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newterm) == -1)
        return -1;
    term->reset_old = 1;
    return 0;
#endif
}

static int
term_restore(const TermState *term)
{
#ifdef OS_WIN32
    if (term->stdinh == INVALID_HANDLE_VALUE)
        return 0;
    if (!SetConsoleMode(term->stdinh, term->mode))
        return -1;
    return 0;
#else
    if (!term->reset_old)
        return 0;
    return tcsetattr(STDIN_FILENO, TCSAFLUSH, &term->old);
#endif
}

char *
read_passphrase(int maxrepeat, int require_reenter, size_t min_len)
{
    TermState term;
    int is_term = 0;
    if (term_disable_echo(&term, &is_term) != 0)
        return NULL;

    if (require_reenter && !is_term)
        require_reenter = 0;

    const size_t bufsize = 4000;
    char *pw[2] = { NULL, NULL };
    pw[0] = VOIDPTR_CAST(char *, sodium_malloc(bufsize));
    if (!pw[0])
        return NULL;
    if (require_reenter) {
        pw[1] = VOIDPTR_CAST(char *, sodium_malloc(bufsize));
        if (!pw[1]) {
            sodium_free(pw[0]);
            return NULL;
        }
    }

    printf("IS_TERM: %d\n", is_term);

    int match = 0;
    int is_eof = 0;
    for (int trial = 0; trial < maxrepeat && !is_eof; ++trial) {
        for (int i = 0; i < (require_reenter ? 2 : 1); ++i) {
            if (is_term)
                printf("%s passphrase: ", i == 0 ? "Enter" : "Reenter");
            else
                fprintf(
                  stderr,
                  "Warning: not a terminal, reading passphrase from stdin\n");
            fflush(stdout);
            int ch;
            size_t pos = 0;
            if (!is_term) {
                // read passphrase from stdin
                if (fgets(pw[i], bufsize, stdin) == NULL) {
                    is_eof = 1;
                    // pos == 0
                } else {
                    is_eof = feof(stdin);
                    char *end = &pw[i][strlen(pw[i])];
                    while (end != pw[i] && (end[-1] == '\r' || end[-1] == '\n'))
                        --end;
                    *end = '\0';
                    pos = end - pw[i];
                }
            } else {
                // read interactive passphrase
                while (pos < bufsize) {
                    #ifdef OS_WIN32
                        ch = _getch();
                    #else
                        ch = fgetc(stdin);
                    #endif
                    switch (ch) {
                    case EOF:
                    case 0x4: // <Ctrl-d>
                        is_eof = 1;
                        goto out;
                    case 0x7f: // <backspace>
                        if (pos > 0)
                            --pos;
                        break;
                    case '\n':
                    case '\r':
                        printf("\n");
                        goto out;
                    default:
                        pw[i][pos++] = ch;
                        break;
                    }
                }
            }
        out:;
            if (is_eof && i == 0 && require_reenter) {
                fprintf(stderr, "\nPremature end of input\n");
                goto ret;
            }
            if (pos == bufsize) {
                fprintf(stderr, "\nPassphrase too long\n");
                goto repeat;
            }
            pw[i][pos] = '\0';
            if (i == 0 && pos == 0) {
                fprintf(stderr, "Empty passphrase forbidden\n");
                goto repeat;
            } else if (i == 0 && pos < min_len) {
                fprintf(stderr,
                        "Passphrase too short, minimum length: %zu\n",
                        min_len);
                goto repeat;
            }
        }
        if (require_reenter && strcmp(pw[0], pw[1]) != 0) {
            fprintf(stderr, "Passphrases dont match\n");
        } else {
            match = 1;
            break;
        }
    repeat:;
    }

ret:
    sodium_free(pw[1]);
    term_restore(&term);
    if (!match) {
        sodium_free(pw[0]);
        return NULL;
    }
    return pw[0];
}

static char *
malloc_strcat(const char *a, const char *b)
{
    assert(a && "a cannot be NULL");
    assert(b && "b cannot be NULL");
    size_t len1 = strlen(a);
    size_t len2 = strlen(b);
    char *buf = VOIDPTR_CAST(char *, malloc(len1 + len2 + 1));
    strcpy(buf, a);
    strcat(buf, b);
    return buf;
}

static int
generate_keypair(PublicKey *pk,
                 SecretKey *sk,
                 uint64_t subkeyid,
                 const char *seed)
{
    unsigned char kdf_masterkey[crypto_kdf_KEYBYTES];

    // the best we can do, given the determinism constraints...
    unsigned char PWSALT[] = "DETSIGN_PWSALT";

    int ret = crypto_pwhash(kdf_masterkey,
                            sizeof kdf_masterkey,
                            seed,
                            strlen(seed),
                            PWSALT,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_MODERATE,
                            crypto_pwhash_ALG_ARGON2ID13);
    if (ret != 0)
        return ret;

    unsigned char signseed[crypto_sign_SEEDBYTES];
    ret = crypto_kdf_derive_from_key(signseed,
                                     sizeof signseed,
                                     subkeyid,
                                     "DETSIGN_KDF_CONTEXT",
                                     kdf_masterkey);
    sodium_memzero(kdf_masterkey, sizeof kdf_masterkey);
    if (ret != 0)
        return ret;

    ret = crypto_sign_seed_keypair(pk->data, sk->data, signseed);
    sodium_memzero(signseed, sizeof signseed);
    return ret;
}

static int
generate_keypair_interactive(PublicKey *pk,
                             SecretKey **sk,
                             uint64_t subkeyid,
                             int require_reenter,
                             int verbose)
{
    assert(sk != NULL);
    *sk = NULL;
    const char *error_msg = NULL;
    int ret;
    char *passphrase = read_passphrase(3, require_reenter, 1);
    if (!passphrase) {
        fprintf(stderr, "Reading passphrase failed\n");
        return 1;
    }
    *sk = VOIDPTR_CAST(SecretKey *, sodium_malloc(sizeof **sk));
    if (!*sk) {
        error_msg = "Error";
        goto err;
    }

    if (verbose)
        printf("Generating keypair\n");
    ret = generate_keypair(pk, *sk, subkeyid, passphrase);
    if (ret != 0) {
        error_msg = "Generating keypair failed";
        goto err;
    }
    if (verbose)
        printf("Done\n");
    ret = 0;
    goto out;
err:
    if (error_msg)
        fprintf(stderr, "%s\n", error_msg);
    ret = 1;
out:
    sodium_free(passphrase);
    if (ret != 0) {
        free(*sk);
        *sk = NULL;
    }
    return ret;
}

static int
write_file_b64(const char *dest,
               const unsigned char *data,
               size_t len,
               int is_private)
{
    FILE *fd;
    if (!is_private) {
        fd = fopen(dest, "w");
    } else {
#ifndef OS_WIN32
        int fdnum = open(dest, O_CREAT | O_WRONLY, 0600);
        fd = fdnum != -1 ? fdopen(fdnum, "w") : NULL;
#else
        fd = fopen(dest, "w");
#endif
    }
    if (!fd)
        return 1;

    const size_t b64_size = 1 + sodium_base64_ENCODED_LEN(len, BASE64_VARIANT);
    char *b64_data = VOIDPTR_CAST(char *, malloc(b64_size));
    sodium_bin2base64(b64_data, b64_size, data, len, BASE64_VARIANT);
    ssize_t n = fwrite(b64_data, strlen(b64_data), 1, fd);
    sodium_memzero(b64_data, b64_size);
    free(b64_data);
    if (n != 1)
        return 1;
    fclose(fd);
    return 0;
}

static int
read_file_b64(const char *path, unsigned char *data, size_t size)
{
    FILE *fd = fopen(path, "r");
    if (!fd)
        return 1;
    const size_t b64_size = sodium_base64_ENCODED_LEN(size, BASE64_VARIANT);
    char *b64_data = VOIDPTR_CAST(char *, malloc(b64_size));
    ssize_t n = fread(b64_data, 1, b64_size, fd);
    sodium_memzero(b64_data, b64_size);
    free(b64_data);
    fclose(fd);
    if (n < 0)
        return 1;

    size_t decoded_len;
    int ret = sodium_base642bin(data,
                                size,
                                b64_data,
                                n,
                                BASE64_IGNORE_CHARS,
                                &decoded_len,
                                NULL,
                                BASE64_VARIANT);
    sodium_memzero(b64_data, b64_size);

    if (ret != 0 || decoded_len != size)
        return 1;
    return 0;
}

static int
feed_stream(crypto_sign_state *sstate, FILE *fd)
{
    if (crypto_sign_init(sstate) != 0)
        return 1;
    unsigned char chunk[16 * 4096];
    ssize_t n = sizeof chunk;
    while (n == sizeof chunk) {
        n = fread(chunk, 1, sizeof chunk, fd);
        if (n < 0)
            return 1;
        if (crypto_sign_update(sstate, chunk, n) != 0)
            return 1;
    }
    return 0;
}

static int
usage_error(const char *error_msg)
{
    fprintf(stderr, "%s\n", error_msg);
    fprintf(stderr, "\n");
    fprintf(stderr, "%s", USAGE_STR);
    return 2;
}

static int
check_file_ext(const char *argname, const char *file, const char *ext)
{
    if (!file)
        return 0;
    size_t lenf = strlen(file);
    size_t lenext = strlen(ext);
    if (lenf > lenext && strcmp(file + lenf - lenext, ext) == 0)
        return 0;
    fprintf(stderr,
            "%s argument does not have required file extension: %s\n",
            argname,
            ext);
    return 1;
}

static int
check_file_exts(const ProgramArgs *args)
{
    if (check_file_ext("PUB", args->pkfile, PUB_FILE_EXT) != 0)
        return 1;
    if (check_file_ext("SEC", args->skfile, SEC_FILE_EXT) != 0)
        return 1;
    if (check_file_ext("SIG", args->sigfile, SIG_FILE_EXT) != 0)
        return 1;
    return 0;
}

static int
do_sign(SecretKey *sk, const char *sigfile, const char *datafile, int verbose)
{
    FILE *stream = stdin;
    if (datafile) {
        stream = fopen(datafile, "r");
        if (!stream) {
            fprintf(stderr, "Opening file %s failed\n", datafile);
            return 1;
        }
    }

    char *sigfile_malloced = NULL;
    if (!sigfile)
        sigfile = sigfile_malloced = malloc_strcat(datafile, SIG_FILE_EXT);

    const char *error_message = NULL;
    int ret;

    if (verbose)
        printf("Creating signature\n");
    crypto_sign_state sstate;
    if (feed_stream(&sstate, stream) != 0) {
        error_message = "Signing failed";
        goto err;
    }

    Signature sig;
    if (crypto_sign_final_create(&sstate, sig.data, NULL, sk->data) != 0) {
        error_message = "Signing failed";
        goto err;
    }

    if (write_file_b64(
          sigfile, sig.data, sizeof sig.data, 0 /* default permissions */) !=
        0) {
        error_message = "Writing signature failed";
        goto err;
    }

    if (verbose)
        printf("Done\n");
    ret = 0;
    goto out;

err:;
    if (error_message)
        fprintf(stderr, "%s\n", error_message);
    ret = 1;
out:
    sodium_memzero(sk->data, sizeof sk->data);
    if (stream != stdin)
        fclose(stream);
    free(sigfile_malloced);
    return ret;
}

static int
mode_gen(const ProgramArgs *args, int argc, char *const *argv)
{
    if (args->sigfile)
        return usage_error("Invalid argument: -d SIG");
    if (!args->pkfile)
        return usage_error("Missing argument: -p PUB");
    if (argc != 1)
        return usage_error("Too many arguments given");
    if (check_file_exts(args) != 0)
        return 1;

    PublicKey pk;
    SecretKey *sk;
    int ret = generate_keypair_interactive(
      &pk, &sk, args->subkeyid, 1 /* require_reenter */, args->verbose);
    if (ret != 0)
        return 1;

    ret = write_file_b64(
      args->pkfile, pk.data, sizeof pk.data, 0 /* default permissions */);
    if (ret != 0)
        goto err;
    if (args->skfile) {
        ret = write_file_b64(
          args->skfile, sk->data, sizeof sk->data, 1 /* private permissions */);
        if (ret != 0)
            goto err;
    }

    if (args->verbose)
        printf("Keypair generated and saved\n");
    sodium_free(sk);
    return 0;
err:
    fprintf(stderr, "Error: writing keyfiles\n");
    sodium_free(sk);
    return 1;
}

static int
mode_gen_sign(const ProgramArgs *args, int argc, char *const *argv)
{
    if (args->skfile)
        return usage_error("Invalid arguments");
    if (argc != 2)
        return usage_error(argc < 2 ? "Missing FILE argument"
                                    : "Too many arguments");
    if (check_file_exts(args) != 0)
        return 1;

    PublicKey oldpk;
    if (args->pkfile) {
        if (read_file_b64(args->pkfile, oldpk.data, sizeof oldpk.data) != 0) {
            fprintf(stderr, "Error: reading existing public key failed\n");
            return 1;
        }
    }

    PublicKey pk;
    SecretKey *sk = NULL;
    if (generate_keypair_interactive(&pk,
                                     &sk,
                                     args->subkeyid,
                                     0 /* no require_reenter */,
                                     args->verbose) != 0)
        return 1;

    if (args->pkfile) {
        if (sodium_memcmp(oldpk.data, pk.data, sizeof pk.data) != 0) {
            fprintf(
              stderr,
              "Error: public keys don't match, wrong passphrase/subkeyid?\n");
            sodium_free(sk);
            return 1;
        }
    }

    int ret = do_sign(sk, args->sigfile, argv[1], args->verbose);
    sodium_free(sk);
    return ret;
}

static int
mode_sign(const ProgramArgs *args, int argc, char *const *argv)
{
    if (args->pkfile || args->has_subkeyid)
        return usage_error("Invalid argument");
    if (argc > 2)
        return usage_error("Too many arguments");
    if (!args->skfile)
        return usage_error("Missing argument: -s SEC");
    if (argc == 1 && !args->sigfile)
        return usage_error("Missing argument");
    if (check_file_exts(args) != 0)
        return 1;

    SecretKey sk;
    if (read_file_b64(args->skfile, sk.data, sizeof sk.data) != 0) {
        fprintf(stderr, "Reading secretkey failed\n");
        return 1;
    }

    return do_sign(&sk, args->sigfile, argv[1], args->verbose);
}

static int
mode_verify(const ProgramArgs *args, int argc, char *const *argv)
{
    if (args->skfile)
        return usage_error("Invalid argument: -s SEC");
    if (!args->pkfile)
        return usage_error("Missing argument: -p PUB");
    if (argc > 2)
        return usage_error("Too many arguments");
    if (argc != 2 && !args->sigfile)
        return usage_error(
          "If FILE argument is not given, argument -d SIG has to be set");
    if (check_file_exts(args) != 0)
        return 1;

    const char *file = "<stdin>";
    FILE *stream = stdin;
    if (argc == 2) {
        file = argv[1];
        stream = fopen(file, "r");
        if (!stream) {
            fprintf(stderr, "Error: opening %s failed\n", file);
            return 1;
        }
    }

    char *sigfile_malloced = NULL;
    const char *sigfile = args->sigfile;
    if (!sigfile)
        sigfile = sigfile_malloced = malloc_strcat(file, SIG_FILE_EXT);

    PublicKey pk;
    const char *error_message = NULL;
    int ret = read_file_b64(args->pkfile, pk.data, sizeof pk.data);
    if (ret != 0) {
        error_message = "Reading public key failed";
        goto err;
    }
    Signature sig;
    ret = ret == 0 ? read_file_b64(sigfile, sig.data, sizeof sig.data) : ret;
    if (ret != 0) {
        error_message = "Reading signature failed";
        goto err;
    }

    crypto_sign_state sstate;
    ret = feed_stream(&sstate, stream);
    if (ret != 0) {
        error_message = "Couldnt read data";
        goto err;
    }

    if (crypto_sign_final_verify(&sstate, sig.data, pk.data) != 0) {
        printf("%s: Bad Signature", file);
        error_message = NULL;
        goto err;
    }
    printf("%s: Good Signature\n", file);
    ret = 0;
    goto out;

err:;
    if (error_message)
        fprintf(stderr, "%s\n", error_message);
    ret = 1;
out:
    fclose(stream);
    free(sigfile_malloced);
    return ret;
}

static int
mode_regen_pub(const ProgramArgs *args, int argc, char *const *argv)
{
    if (!args->pkfile || !args->skfile)
        return usage_error("Missing argument");
    if (args->has_subkeyid || args->sigfile)
        return usage_error("Invalid argument");
    if (argc != 1)
        return usage_error("Too many arguments");
    if (check_file_exts(args) != 0)
        return 1;

    SecretKey sk;
    if (read_file_b64(args->skfile, sk.data, sizeof sk.data) != 0) {
        fprintf(stderr, "Reading secretkey failed\n");
        return 1;
    }

    PublicKey pk;
    int ret = crypto_sign_ed25519_sk_to_pk(pk.data, sk.data);
    sodium_memzero(sk.data, sizeof sk.data);
    if (ret != 0) {
        fprintf(stderr, "Recreating public key failed\n");
        return 1;
    }

    if (write_file_b64(
          args->pkfile, pk.data, sizeof pk.data, 0 /* default permissions */) !=
        0) {
        fprintf(stderr, "Writing publickey failed\n");
        return 1;
    }

    if (args->verbose)
        printf("Done\n");
    return 0;
}

static int
parse_args(ProgramArgs *args, int *argcp, char **argv)
{
    assert(argcp);
    assert(args);
    assert(argv);
    if (*argcp < 1)
        return 1;

    const int argc = *argcp;
    int optch = 0;
    int argdest = 1;
    int have_mode = 0;

    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        switch (optch) {
        case 0:
            if (strcmp(arg, "--") == 0) {
                for (++i; i < argc; ++i)
                    argv[argdest++] = argv[i];
            } else if (arg[0] == '-') {
                if (arg[1] == '\0' || arg[2] != '\0')
                    return usage_error("Invalid option in arguments");
                switch (arg[1]) {
                case 'p':
                case 's':
                case 'd':
                case 'i':
                    optch = arg[1];
                    break;
                case 'v':
                    args->verbose = 1;
                    break;
                default:
                    return usage_error("Invalid option in arguments");
                }
            } else {
                if (!have_mode) {
                    if (strcmp(arg, "gen") == 0)
                        args->mode = MODE_GEN;
                    else if (strcmp(arg, "gen-sign") == 0)
                        args->mode = MODE_GEN_AND_SIGN;
                    else if (strcmp(arg, "sign") == 0)
                        args->mode = MODE_SIGN;
                    else if (strcmp(arg, "verify") == 0)
                        args->mode = MODE_VERIFY;
                    else if (strcmp(arg, "regen-pub") == 0)
                        args->mode = MODE_REGEN_PUB;
                    else
                        return usage_error("Invalid command given");
                    have_mode = 1;
                } else {
                    argv[argdest++] = arg;
                }
            }
            break;
        case 'p':
            args->pkfile = arg;
            optch = 0;
            break;
        case 's':
            args->skfile = arg;
            optch = 0;
            break;
        case 'd':
            args->sigfile = arg;
            optch = 0;
            break;
        case 'i': {
            char *end = NULL;
            args->subkeyid = strtoull(arg, &end, 10);
            if (!end || *end != '\0')
                return usage_error("Invalid SUBKEYID");
            args->has_subkeyid = 1;
            optch = 0;
            break;
        }
        default:
            assert(0 && "BUG");
            break;
        }
    }

    if (optch != 0) {
        return usage_error("Missing argument for option");
    }

    *argcp = argdest;
    argv[argdest] = NULL;

    return 0;
}

int
main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        fprintf(stderr, "Crypto initialization failed\n");
        return 3;
    }

    ProgramArgs args = { MODE_INVALID };
    int ret = parse_args(&args, &argc, argv);
    if (ret != 0)
        return ret;

    switch (args.mode) {
    case MODE_INVALID:
        fprintf(stderr, "%s", USAGE_STR);
        return 2;
    case MODE_GEN:
        return mode_gen(&args, argc, argv);
    case MODE_GEN_AND_SIGN:
        return mode_gen_sign(&args, argc, argv);
    case MODE_SIGN:
        return mode_sign(&args, argc, argv);
    case MODE_VERIFY:
        return mode_verify(&args, argc, argv);
    case MODE_REGEN_PUB:
        return mode_regen_pub(&args, argc, argv);
    }

    return 99;
}
