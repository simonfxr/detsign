#include <sodium.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <termios.h>
#include <unistd.h>

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

static int
term_disable_echo(struct termios *oldterm)
{
    if (tcgetattr(STDIN_FILENO, oldterm) == -1)
        return -1;
    struct termios newterm = *oldterm;
    newterm.c_lflag = newterm.c_lflag & ~(ECHO | ICANON);
    newterm.c_cc[VMIN] = 1;
    newterm.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newterm) == -1)
        return -1;
    return 0;
}

static int
term_restore(const struct termios *term)
{
    return tcsetattr(STDIN_FILENO, TCSAFLUSH, term);
}

char *
read_passphrase(int maxrepeat, int require_reenter)
{
    struct termios term;
    if (term_disable_echo(&term) != 0)
        return NULL;

    const size_t bufsize = 4000;
    char *pw[2] = { NULL, NULL };
    pw[0] = sodium_malloc(bufsize);
    if (require_reenter)
        pw[1] = sodium_malloc(bufsize);
    if (!pw[0] || (require_reenter && !pw[1]))
        return NULL;

    int match = 0;
    int is_eof = 0;
    for (int try = 0; try < maxrepeat && !is_eof; ++try) {
        for (int i = 0; i < (require_reenter ? 2 : 1); ++i) {
            printf("%s passphrase: ", i == 0 ? "Enter" : "Renter");
            fflush(stdout);
            int ch;
            size_t pos = 0;
            while (pos < bufsize) {
                switch ((ch = fgetc(stdin))) {
                case EOF:
                case 0x4: // <Ctrl-d>
                    is_eof = 1;
                    goto out;
                case 0x7f: // <backspace>
                    if (pos > 0)
                        --pos;
                    break;
                case '\n':
                    printf("\n");
                    goto out;
                default:
                    pw[i][pos++] = ch;
                    break;
                }
            }
        out:;
            if (is_eof && i == 0) {
                fprintf(stderr, "\nPremature end of input\n");
                goto ret;
            }
            if (pos == bufsize) {
                fprintf(stderr, "\nPassphrase too long\n");
                goto ret;
            }
            pw[i][pos] = '\0';
        }
        if (require_reenter && strcmp(pw[0], pw[1]) != 0) {
            fprintf(stderr, "Passphrases dont match\n");
        } else {
            match = 1;
            break;
        }
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

static int
generate_keypair(PublicKey *pk, SecretKey *sk, const char *seed, size_t seedlen)
{
    unsigned char derivedseed[crypto_sign_SEEDBYTES];
    unsigned char empty[1] = { 0 };
    int ret = crypto_pwhash(derivedseed,
                            crypto_sign_SEEDBYTES,
                            seed,
                            seedlen,
                            empty,
                            crypto_pwhash_OPSLIMIT_MODERATE,
                            crypto_pwhash_MEMLIMIT_MODERATE,
                            crypto_pwhash_ALG_ARGON2ID13);
    if (ret != 0)
        return ret;
    ret = crypto_sign_seed_keypair(pk->data, sk->data, derivedseed);
    sodium_memzero(derivedseed, sizeof derivedseed);
    return ret;
}

static int
generate_keypair_interactive(PublicKey *pk, SecretKey **sk, int require_reenter)
{
    assert(sk != NULL);
    *sk = NULL;
    const char *error_msg = NULL;
    int ret;
    char *passphrase = read_passphrase(3, require_reenter);
    if (!passphrase) {
        fprintf(stderr, "Reading passphrase failed\n");
        return 1;
    }
    size_t len = strlen(passphrase);
    if (len < 1) {
        error_msg = len == 0 ? "Empty passphrase" : "Passphrase too short";
        goto err;
    }
    *sk = sodium_malloc(sizeof **sk);
    if (!*sk) {
        error_msg = "Error";
        goto err;
    }

    printf("Generating keypair\n");
    ret = generate_keypair(pk, *sk, passphrase, strlen(passphrase));
    if (ret != 0) {
        error_msg = "Generating keypair failed";
        goto err;
    }
    sodium_free(passphrase);
    passphrase = NULL;
    return 0;

err:
    if (passphrase)
        sodium_free(passphrase);
    if (*sk) {
        free(*sk);
        *sk = NULL;
    }
    if (error_msg)
        fprintf(stderr, "%s\n", error_msg);
    return 1;
}

static int
write_file(const char *dest,
           const char *suff,
           const unsigned char *data,
           size_t len)
{
    char filename[4096];
    int ret = snprintf(filename, sizeof filename, "%s%s", dest, suff);
    if (ret >= sizeof filename)
        return 1;
    FILE *fd = fopen(filename, "w");
    if (!fd)
        return 1;
    ssize_t n = fwrite(data, len, 1, fd);
    if (n != 1)
        return 1;
    fclose(fd);
    return 0;
}

static int
mode_generate(const char *keydest)
{
    PublicKey pk;
    SecretKey *sk;
    int ret = generate_keypair_interactive(&pk, &sk, 1 /* require_reenter */);
    if (ret != 0)
        return 1;

    printf("Writing keyfiles\n");
    ret = write_file(keydest, ".detsign.pub", pk.data, sizeof pk.data);
    if (ret != 0)
        goto err;
    ret = write_file(keydest, ".detsign.sec", sk->data, sizeof sk->data);
    if (ret != 0)
        goto err;

    printf("Keypair generated and saved\n");
    sodium_free(sk);
    return 0;
err:
    fprintf(stderr, "Error writing keyfiles\n");
    sodium_free(sk);
    return 1;
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
mode_regenerate_and_sign(FILE *stream, const char *sigdest)
{
    PublicKey pk;
    SecretKey *sk = NULL;
    const char *error_msg = NULL;
    int ret =
      generate_keypair_interactive(&pk, &sk, 0 /* no require_reenter */);
    if (ret != 0)
        return 1;
    printf("Creating signature\n");
    crypto_sign_state sstate;
    if (feed_stream(&sstate, stream) != 0) {
        error_msg = "Signing failed";
        goto err;
    }
    Signature sig;
    if (crypto_sign_final_create(&sstate, sig.data, NULL, sk->data) != 0) {
        error_msg = "Signing failed";
        goto err;
    }

    if (write_file(sigdest, ".detsign.sig", sig.data, sizeof sig.data) != 0) {
        error_msg = "Writing signature failed";
        goto err;
    }

    printf("Done\n");
    ret = 0;
    goto out;

err:;
    fprintf(stderr, "%s\n", error_msg);
    ret = 1;
out:;
    sodium_free(sk);
    return ret;
}

static int
read_file(const char *path, unsigned char *dest, size_t size)
{
    FILE *fd = fopen(path, "r");
    if (!fd)
        return 1;
    ssize_t n = fread(dest, size, 1, fd);
    fclose(fd);
    return n == 1 ? 0 : 1;
}

static int
mode_verify(FILE *data_stream, const char *pkfile, const char *sigfile)
{
    PublicKey pk;
    const char *error_message = NULL;
    int ret = read_file(pkfile, pk.data, sizeof pk.data);
    if (ret != 0) {
        error_message = "Reading public key failed";
        goto err;
    }
    Signature sig;
    ret = ret == 0 ? read_file(sigfile, sig.data, sizeof sig.data) : ret;
    if (ret != 0) {
        error_message = "Reading signature failed";
        goto err;
    }

    crypto_sign_state sstate;
    ret = feed_stream(&sstate, data_stream);
    if (ret != 0) {
        error_message = "Couldnt read data";
        goto err;
    }

    if (crypto_sign_final_verify(&sstate, sig.data, pk.data) != 0) {
        error_message = "Bad Signature!";
        goto err;
    }

    printf("Good signature\n");
    return 0;
err:;
    fprintf(stderr, "%s\n", error_message);
    return 1;
}

int
main(int argc, char *argv[])
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init() failed\n");
        return 1;
    }
    // int ret = mode_generate("out");

    // FILE *in = fopen(argv[1], "r");
    // int ret = mode_regenerate_and_sign(in, "out");

    return mode_verify(stdin, "out.detsign.pub", "out.detsign.sig");
}
