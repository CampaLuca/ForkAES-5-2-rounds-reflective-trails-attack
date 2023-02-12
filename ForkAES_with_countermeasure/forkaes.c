#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "aes_utilities.c"
#include "forkaes_configuration.h"

void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* tweak, uint8_t* left, uint8_t* right);
void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* tweak, int side);
void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* tweak, int side);


void encrypt(uint8_t* plaintext, uint8_t* key, uint8_t* tweak, uint8_t* left, uint8_t* right) {
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);
    uint8_t round_tweaks[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    TweakExpansion(round_tweaks, tweak, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;
    uint8_t* round_tweak;


    for (int i = 0; i < HEADER_ROUNDS; i++) {
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
        }
        add(plaintext, round_key);
        add(plaintext, round_tweak);

        forward_round(plaintext);
        free(round_key);
    }


    uint8_t* middle_plaintext = malloc(16);
    for (int i = 0; i < 16; i++) {
        middle_plaintext[i] = plaintext[i];
    }

    // ------------------------------------------------------------------ left side
    for (int i = HEADER_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS; i++) {
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
        }

        add(plaintext, round_key);
        add(plaintext, round_tweak);

       forward_round(plaintext);

        free(round_key);
    }
    // add round key + tweak at the end
    int index = HEADER_ROUNDS+LEFT_ROUNDS;
    round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[index*BLOCK_SIZE+j];
        }

    add(plaintext, round_key);
    add(plaintext, round_tweak);
    free(round_key);
    

    // printf("Left Side done: ");
    // pretty_print(plaintext, BLOCK_SIZE);
    // saving left side into right array
    for (int i = 0; i < 16; i++) {
        left[i] = plaintext[i];
    }

    // -------------------------------------------------------------- right side
   
    for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i++) {
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
        }

        add(middle_plaintext, round_key);
        add(middle_plaintext, round_tweak);

       forward_round(middle_plaintext);

        free(round_key);
    }
    // add round key + tweak at the end
    index = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS;
    round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[index*BLOCK_SIZE+j];
        }

    add(middle_plaintext, round_key);
    add(middle_plaintext, round_tweak);
    free(round_key);
    

    // printf("Right Side done: ");
    // pretty_print(middle_plaintext, BLOCK_SIZE);

    // saving right side into right array
    for (int i = 0; i < 16; i++) {
        right[i] = middle_plaintext[i];
    }

}


void decrypt(uint8_t* ciphertext, uint8_t* key, uint8_t* tweak, int side) {      // side = 0 or side = 1
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);
    uint8_t round_tweaks[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    TweakExpansion(round_tweaks, tweak, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;
    uint8_t* round_tweak;


    if (side == 0) { // LEFT SIDE

        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i > HEADER_ROUNDS; i--) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }
            add(ciphertext, round_key);
            add(ciphertext, round_tweak);

            inverse_round(ciphertext);
            free(round_key);
        }

        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[HEADER_ROUNDS*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[HEADER_ROUNDS*BLOCK_SIZE+j];
        }

        add(ciphertext, round_key);
        add(ciphertext, round_tweak);
        free(round_key);
    }

    if (side == 1) { // RIGHT SIDE

        for (int i = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i > HEADER_ROUNDS+LEFT_ROUNDS; i--) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }
            add(ciphertext, round_key);
            add(ciphertext, round_tweak);

            inverse_round(ciphertext);
            free(round_key);
        }

        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
            round_tweak[j] = round_tweaks[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
        }
       
        add(ciphertext, round_key);
        add(ciphertext, round_tweak);
        free(round_key);
    }

    // header

    for (int i = HEADER_ROUNDS-1; i >= 0; i--) {
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[i*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
        }
        
        inverse_round(ciphertext);
        add(ciphertext, round_key);
        add(ciphertext, round_tweak);
        free(round_key);
    }


  

}


void compute_sibling(uint8_t* c0, uint8_t* key, uint8_t* tweak, int side) {
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);
    uint8_t round_tweaks[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    TweakExpansion(round_tweaks, tweak, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    uint8_t* round_key;
    uint8_t* round_tweak;

    if (side == 0) {    // LEFT
        // decrypt left  encrypt right
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i > HEADER_ROUNDS; i--) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }
            add(c0, round_key);
            add(c0, round_tweak);

            inverse_round(c0);
            free(round_key);
        }
        // add round key + tweak at the end
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[HEADER_ROUNDS*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[HEADER_ROUNDS*BLOCK_SIZE+j];
        }

        add(c0, round_key);
        add(c0, round_tweak);
        free(round_key);

        // encrypt right
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i++) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }

            add(c0, round_key);
            add(c0, round_tweak);

            forward_round(c0);

            free(round_key);
        }
        // add round key + tweak at the end
        int index = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS;
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[index*BLOCK_SIZE+j];
        }

        add(c0, round_key);
        add(c0, round_tweak);
        free(round_key);

        // printf("From Left to Right: ");
        // pretty_print(c0, BLOCK_SIZE);
    }

    if (side == 1) {    // RIGHT
        // decrypt right - encrypt left
        for (int i = HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS; i > HEADER_ROUNDS+LEFT_ROUNDS; i--) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }
            add(c0, round_key);
            add(c0, round_tweak);

            inverse_round(c0);
            free(round_key);
        }

        // add round key + tweak at the end
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
            round_tweak[j] = round_tweaks[BLOCK_SIZE*(HEADER_ROUNDS+LEFT_ROUNDS)+j];
        }

        add(c0, round_key);
        add(c0, round_tweak);
        free(round_key);


        for (int i = HEADER_ROUNDS; i < HEADER_ROUNDS+LEFT_ROUNDS; i++) {
            round_key = malloc(16);
            round_tweak = malloc(16);
            for (int j = 0; j < 16; j++) {
                round_key[j] = round_keys[i*BLOCK_SIZE+j];
                round_tweak[j] = round_tweaks[i*BLOCK_SIZE+j];
            }

            add(c0, round_key);
            add(c0, round_tweak);

           forward_round(c0);

            free(round_key);
        }
        // add round key + tweak at the end
        int index = HEADER_ROUNDS+LEFT_ROUNDS;
        round_key = malloc(16);
        round_tweak = malloc(16);
        for (int j = 0; j < 16; j++) {
            round_key[j] = round_keys[index*BLOCK_SIZE+j];
            round_tweak[j] = round_tweaks[index*BLOCK_SIZE+j];
        }
     

        add(c0, round_key);
        add(c0, round_tweak);
        free(round_key);

        
    }
}


void test() {
srand(time(NULL));
    uint8_t* c0_left = malloc(16);
    uint8_t* c1_right = malloc(16);
    uint8_t* plaintext = malloc(16);
    for (int i = 0; i < 16; i++) {
        plaintext[i] = (uint8_t)(rand() % 256);
    }

    uint8_t* key = malloc(16);
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }

    uint8_t* tweak = malloc(16);
    for (int i = 0; i < 16; i++) {
        tweak[i] = (uint8_t)(rand() % 256);
    }

    pretty_print("Plaintext:\n", plaintext, BLOCK_SIZE);
    pretty_print("Key:\n", key, BLOCK_SIZE);
    pretty_print("Tweak:\n", tweak, BLOCK_SIZE);

    encrypt(plaintext, key, tweak, c0_left, c1_right);
    pretty_print("Left:\n", c0_left, BLOCK_SIZE);
    pretty_print("Right:\n", c1_right, BLOCK_SIZE);

    decrypt(c0_left, key, tweak, 0);
    pretty_print("Plaintext:\n", c0_left, BLOCK_SIZE);

    decrypt(c1_right, key, tweak, 1);
    pretty_print("Plaintext:\n", c1_right, BLOCK_SIZE);

    for (int i = 0; i < 16; i++) {
        plaintext[i] = c0_left[i];
    }
    encrypt(plaintext, key, tweak, c0_left, c1_right);

    compute_sibling(c0_left, key, tweak, 0);
    pretty_print("Right:\n", c0_left, BLOCK_SIZE);
    compute_sibling(c1_right, key, tweak, 1);
    pretty_print("Left:\n", c1_right, BLOCK_SIZE);


}

int main(int argc, char** argv) {
    test();
    return 0;
}