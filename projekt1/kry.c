/// Author: Le Duy Nguyen, xnguye27 VUT FIT 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_LEN 26
#define LETTER_OFFSET 'A'

int POSSIBLE_KEY_A[] = {1, 3, 5, 7, 9 ,11, 15, 17, 19, 21, 23, 25, 0};
double CZECH_FREQUENCY[ALPHABET_LEN] = {
    0.084548, 0.015582, 0.025557, 0.036241, 0.106751, // a b c d e
    0.002732, 0.002729, 0.012712, 0.076227, 0.021194, // f g h i j
    0.037367, 0.038424, 0.032267, 0.066167, 0.086977, // k l m n o
    0.034127, 0.000013, 0.049136, 0.053212, 0.057694, // p q r s t
    0.039422, 0.046616, 0.000088, 0.000755, 0.029814, // u v w x y
    0.031939                                          // z
};

char *ERROR_MSG[] = {
    [1] = "Invalid Arguments",
    "Too Many Arguments",
    "File Not Found",
    "Out Of Memory",
    "Character Out Of Range",
};

enum error {
    Ok,
    InvalidArguments,
    TooManyArguments,
    FileNotFound,
    OutOfMemory,
    CharacterOutOfRange,
};

enum Command {
    Encrypt,
    Decrypt,
    Crack,
};

typedef struct key {
    char a;
    char b;
} Key;

typedef struct {
    enum Command cmd;
    Key key;
    char *text;
    FILE *output;
} Arguments;

void print_error_msg();

char encrypt_char(const char ch, const Key key);
void encrypt(const char *text, const Key key, char *output);

char decrypt_char(const char ch, const Key key);
void decrypt(const char *text, const Key key, char *output);

Key guess_key(const char *text);

Arguments parse_args(int argc, char **argv);
void free_args(Arguments *args);

enum error ERROR = Ok;

int main(int argc, char **argv) {
    Arguments args = parse_args(argc, argv);

    if (!ERROR) {
        int len = strlen(args.text);
        char output[len + 1];

        switch (args.cmd) {
            case Encrypt:
                encrypt(args.text, args.key, output);
                break;
            case Decrypt:
                decrypt(args.text, args.key, output);
                break;
            case Crack: {
                Key guessed_key = guess_key(args.text);

                if (!ERROR) {
                    decrypt(args.text, guessed_key, output);
                    printf("a=%i,b=%i\n", guessed_key.a, guessed_key.b);
                }

                break;
            }
        }

        fprintf(args.output, "%s", output);
    }

    if (ERROR) {
        print_error_msg();
    }

    free_args(&args);
    return ERROR;
}

void print_error_msg() {
    if (ERROR) {
        fprintf(stderr, "ERROR: %s\n", ERROR_MSG[ERROR]);
    }
}

int get_file_size(FILE *file) {
    fseek(file, 0L, SEEK_END);
    int file_size = ftell(file);
    rewind(file);
    return file_size;
}

Arguments parse_args(int argc, char **argv) {
    Arguments args;
    args.key.a = -1;
    args.key.b = -1;
    args.text = NULL;
    args.output = stdout;

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        if (strcmp(arg, "-e") == 0) {
            args.cmd = Encrypt;
        } else if (strcmp(arg, "-d") == 0) {
            args.cmd = Decrypt;
        } else if (strcmp(arg, "-c") == 0) {
            args.cmd = Crack;
        } else if (strcmp(arg, "-a") == 0) {
            args.key.a = atoi(argv[++i]);
        } else if (strcmp(arg, "-b") == 0) {
            args.key.b = atoi(argv[++i]);
        } else if (strcmp(arg, "-f") == 0) {
            FILE *input = fopen(argv[++i], "r");
            if (!input) {
                ERROR = FileNotFound;
                break;
            }

            int file_size = get_file_size(input);
            args.text = malloc(sizeof(char) * file_size);

            if (!args.text) {
                ERROR = OutOfMemory;
                break;
            }

            int ch;
            int index = 0;

            while ((ch = fgetc(input)) != EOF) {
                args.text[index++] = ch;
            }

            args.text[index] = '\0';
            fclose(input);
        } else if (strcmp(arg, "-o") == 0) {
            args.output = fopen(argv[++i], "w");

            if (!args.output) {
                ERROR = FileNotFound;
                break;
            }
        } else {
            if (args.text) {
                ERROR = TooManyArguments;
                break;
            }

            args.text = strdup(arg);

            if (!args.text) {
                ERROR = OutOfMemory;
                break;
            }
        }

    }

    return args;

}

void free_args(Arguments *args) {
    if (args) {
        if (args->text) free(args->text);
        fclose(args->output);
    }
}

char encrypt_char(const char ch, const Key key) {
    if (isspace(ch)) {
        return ch;
    }

    char tmp = toupper(ch);

    if (tmp < LETTER_OFFSET || tmp > LETTER_OFFSET + ALPHABET_LEN) {
        ERROR = CharacterOutOfRange;
        return ch;
    }

    int index = tmp - LETTER_OFFSET;
    char encrypted = (key.a * index + key.b) % ALPHABET_LEN;
    return encrypted + LETTER_OFFSET;
}

void encrypt(const char *text, const Key key, char *output) {
    int i = 0;

    while (text[i]) {
        char ch = encrypt_char(text[i], key);

        if (ERROR) {
            print_error_msg();
            ERROR = Ok;
            continue;
        }

        output[i++] = ch;
    }

    output[i] = '\0';
}

extern inline int multiplicative_inverse(int num) {
    switch (num) {
        case 1 : return 1;
        case 3 : return 9;
        case 5 : return 21;
        case 7 : return 15;
        case 9 : return 3;
        case 11: return 19;
        case 15: return 7;
        case 17: return 23;
        case 19: return 11;
        case 21: return 5;
        case 23: return 17;
        case 25: return 25;
        default: return 0;
    }
}

char decrypt_char(const char ch, const Key key) {
    if (isspace(ch)) {
        return ch;
    }

    char tmp = toupper(ch);

    if (tmp < LETTER_OFFSET || tmp > LETTER_OFFSET + ALPHABET_LEN) {
        ERROR = CharacterOutOfRange;
        return ch;
    }

    int index = ch - LETTER_OFFSET;
    /// the later evaluation of `x - b` shouldn't be negative
    /// thanks to chinese remainder theorem, the extra `ALPHABET_LEN` we put 
    /// in here will not affect the result
    int x = index + ALPHABET_LEN; 
    char decrypted = multiplicative_inverse(key.a) * (x - key.b) % ALPHABET_LEN;
    return decrypted + LETTER_OFFSET;

}

void decrypt(const char *text, const Key key, char *output) {
    int i = 0;

    while (text[i]) {
        char ch = decrypt_char(text[i], key);

        if (ERROR) {
            print_error_msg();
            ERROR = Ok;
            continue;
        }

        output[i++] = ch;
    }

    output[i] = '\0';
}

/// Cracking time

void get_frequency(const char *text, double output[ALPHABET_LEN]) {
    unsigned cnt = 0;

    /// initialize the frequencies
    for (int i = 0; i < ALPHABET_LEN; i++) {
        output[i] = 0.0;
    }

    for (int i = 0; text[i]; i++) {
        if (text[i] == ' ' || text[i] == '\n') {
            continue;
        }

        output[text[i] - LETTER_OFFSET]++;
        cnt++;
    }

    for (int i = 0; i < ALPHABET_LEN; i++) {
        output[i] /= cnt;
    }
}

/// https://en.wikipedia.org/wiki/Chi-squared_test
double chi_squared_test(const double *frequency, int len) {
    double res = 0.0;

    for (int i = 0; i < ALPHABET_LEN; i++) {
        double expected = CZECH_FREQUENCY[i];
        double observed = frequency[i];
        res += observed * observed / expected - len;
    }

    return res;
}

Key guess_key(const char *text) {
    int text_len = strlen(text);

    double frequency[ALPHABET_LEN];
    char buffer[text_len + 1];
    Key key = {.a = 1, .b = 0};

    get_frequency(text, frequency);
    double lowest_chi_value = 1e10;

    for (int i = 0; POSSIBLE_KEY_A[i]; i++) {
        for (char key_b = 0; key_b < ALPHABET_LEN; key_b++) {
            Key current_key = { 
                .a = POSSIBLE_KEY_A[i], 
                .b = key_b 
            };

            decrypt(text, current_key, buffer);
            get_frequency(buffer, frequency);
            double chi_value = chi_squared_test(frequency, text_len);

            if (chi_value < lowest_chi_value) {
                lowest_chi_value = chi_value;
                key = current_key;
            }
        }
    }

    return key;
}
