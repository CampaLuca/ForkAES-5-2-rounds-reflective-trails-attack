#include "forkaes.c"
#include <stdint.h>
#include <sys/types.h>


// K7 container
uint8_t key_bytes_possibilities_counter[16][256];
uint8_t key[16];


/*
* Data Structure used by the thread
*/
struct arg_struct {
    int exp;
    int index;
    uint8_t* t1;
    uint8_t* t2;
    uint8_t* tweak1;
    uint8_t* tweak2;
    int column;
    int byte_number;
    int key_number;
};


void* attack_byte_thread(void *arguments) {
    struct arg_struct *args = arguments;
    int exp = args->exp;
    int index = args->index;
    uint8_t* possible_t1_value = args->t1;
    uint8_t* possible_t2_value = args->t2;
    uint8_t* tweak1 = args->tweak1;
    uint8_t* tweak2 = args->tweak2;
    int column = args->column;
    int byte_number = args->byte_number;

    //printf("%d\n", index);
    int new_exp = 8 - exp;
    //printf("%u -> %x\n",index*(1<<new_exp), (unsigned int)(((index+1)*(((1<<new_exp))))-1) ); 
    uint8_t tested_t1[16];
    uint8_t tested_t2[16];

    for (unsigned int key = index*(1<<new_exp); key <= (unsigned int)(((index+1)*(((1<<new_exp))))-1); key++) {
        
        for (int bb = 0; bb < 16; bb++) {
            tested_t1[bb] = possible_t1_value[bb];
            tested_t2[bb] = possible_t2_value[bb];
        }

        uint8_t key0 = (uint8_t)(key & 0xFF);
        

        tested_t1[4*column+byte_number] ^= (uint8_t)key0;
        tested_t2[4*column+byte_number] ^= (uint8_t)key0;
        
        inverse_sub_bytes(tested_t1);
        inverse_sub_bytes(tested_t2);
        
        add(tested_t1, tweak1);
        add(tested_t2, tweak2);

        inverse_round(tested_t1);
        inverse_round(tested_t2);

        int risultato = 1;
        for (int bb = 0; bb < 16; bb++) {
            if ((tested_t1[bb]^tested_t2[bb]) > 0) {
                risultato = 0;
            }
        }

        if (risultato == 1) {
            key_bytes_possibilities_counter[4*column+byte_number][key0]++;
        }


    }
  
    pthread_exit(NULL);
}


void find_intermediate_key_solution(uint8_t** keys, int number_of_keys, uint8_t* chosen_valid_key) {
    srand(time(NULL));
    uint8_t* tweak1 = (uint8_t*) calloc(16, sizeof(uint8_t));
    uint8_t* tweak2 = (uint8_t*) calloc(16, sizeof(uint8_t));
    uint8_t tweak_difference = (uint8_t)(rand() % 256);

    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 2; r++) {
            tweak1[r+c*4] = (uint8_t)(rand() % 256);
        }
    }
   

    uint8_t* base_c = malloc(16);
    for (int i = 0; i < 16; i++) {
            base_c[i] = (uint8_t)(rand() % 256);
    }


    uint8_t* valid_ids = (uint8_t*) calloc(number_of_keys,sizeof(uint8_t));
    uint8_t possible_t1_values[256][16];
    uint8_t possible_t2_values[256][16];

    for (int diff_byte = 0; diff_byte < 16; diff_byte++) {   

        for (int i = 0; i < 16; i++) {
            tweak2[i] = tweak1[i];
        }
        tweak2[diff_byte] = tweak1[diff_byte] ^ tweak_difference;
        
        // compute with tweak 1
        // tweak 1
        for (int possible_c1_value = 0; possible_c1_value < 256; possible_c1_value++) {
            uint8_t* c1_tilde = malloc(16);
            for (int i = 0; i < 16; i++) {
                c1_tilde[i] = base_c[i];
            }
            c1_tilde[diff_byte] = (uint8_t)possible_c1_value;

            shift_rows(c1_tilde);
            mixColumns(c1_tilde);
            add(c1_tilde, tweak1);
            compute_sibling(c1_tilde, key, tweak1, 1);
            add(c1_tilde, tweak1);
            inverseMixedColumn(c1_tilde);
            inv_shift_rows(c1_tilde);
            
            for (int i = 0; i < 16; i++) {
                possible_t1_values[possible_c1_value][i] = c1_tilde[i];
            }
            
            free(c1_tilde);
        }

        // compute with tweak 2
        // tweak 2
        for (int possible_c1_value = 0; possible_c1_value < 256; possible_c1_value++) {
            uint8_t* c1_tilde = malloc(16);
            for (int i = 0; i < 16; i++) {
                c1_tilde[i] = base_c[i];
            }
            c1_tilde[diff_byte] = (uint8_t)possible_c1_value;

            shift_rows(c1_tilde);
            mixColumns(c1_tilde);
            add(c1_tilde, tweak2);
            compute_sibling(c1_tilde, key, tweak2, 1);
            add(c1_tilde, tweak2);
            inverseMixedColumn(c1_tilde);
            inv_shift_rows(c1_tilde);
            
            for (int i = 0; i < 16; i++) {
                possible_t2_values[possible_c1_value][i] = c1_tilde[i];
            }
            
            free(c1_tilde);
        }

        // FINDING A RIGHT COUPLE IN ORDER TO FIND THE KEY BYTE
        int indext1 = -1;
        int indext2 = -1;
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                indext1 = -1;
                indext2 = -1;

                int result = 1;
                for (int byte = 0; byte < 16; byte++) {
                    if (byte != diff_byte) {
                        if ((possible_t1_values[i][byte]^possible_t2_values[j][byte]) > 0) {
                            result = 0;
                            break;
                        }
                    }
                }

                    
                if (result == 1) {
                    result = 0;
                    for (int poss = 0; poss < 127; poss++) {
                        if ((possible_t1_values[i][diff_byte]^possible_t2_values[j][diff_byte]) == out_diff_for_tweak[(int)tweak_difference-1][poss]) {
                            result = 1;
                            break;
                        } 
                    }

                    if (result == 1) {
                        indext1 = i;
                        indext2 = j;
                        break;
                    }
                    
                }
                
            }
        
        }

                
        int cc = 0;
        if (indext1 > -1 && indext2 > -1) { // I gound a couple to use in order to validate the key

            for (int i = 0; i < number_of_keys; i++) {

                if (valid_ids[i] == 1) {
                    continue;
                }

                uint8_t* k7 = (uint8_t*) malloc(16*sizeof(uint8_t));
                

                for (int j = 0; j < 16; j++) {
                    k7[j] = keys[i][j]; // a copy of the key - this is k7
                }

                uint8_t* t1 = (uint8_t*) malloc(16*sizeof(uint8_t));
                uint8_t* t2 = (uint8_t*) malloc(16*sizeof(uint8_t));

                for (int in = 0; in < 16; in++) {
                    t1[in] = possible_t1_values[indext1][in];
                    t2[in] = possible_t2_values[indext2][in];
                }

                add(t1, k7);
                inverse_sub_bytes(t1);
                add(t1, tweak1);
                inverseMixedColumn(t1);
                inv_shift_rows(t1);

                add(t2, k7);
                inverse_sub_bytes(t2);
                add(t2, tweak2);
                inverseMixedColumn(t2);
                inv_shift_rows(t2);

                int risultato = 1;
                for (int bb = 0; bb < 16; bb++) {
                    if ((t1[bb]^t2[bb]) > 0) {
                        risultato = 0;
                    }
                }

                if (risultato == 0) {
                    valid_ids[i] = 1;
                }

                free(t1);
                free(t2);
                free(k7);

            }

        }
    }

    int cc = 0;
    for (int i = 0; i < number_of_keys; i++) {
        if (valid_ids[i] == 0) {
            cc++;
            // for (int bb = 0; bb < 16; bb++) { // PRINTING FOR DEBUGGING
            //     printf("%x ", keys[i][bb]);
            // }
            // printf("\n");
        }
    }
    printf("Number of tested keys successfully: %d\n", cc); 

    if (cc == 1) {
        for (int i = 0; i < number_of_keys; i++) {
            if (valid_ids[i] == 0) {
                for (int bb = 0; bb < 16; bb++) {
                    chosen_valid_key[bb] =  keys[i][bb];
                }
                break;
            }
        }
    } else {
        printf("Repeat the process ... More than one possible keys where found\n");
    }
    free(tweak1);
    free(tweak2);
    free(base_c);
    free(valid_ids);
}


void attack_byte(int column, int byte_number, int start_side, int key_number) {
    srand(time(NULL));

    /*
    * Launch a thread overy 0.100 seconds
    * Mandatory for the nanosleep function
    */
    struct timespec ts;
    int msec = 100;
    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;


    uint8_t* t1 = (uint8_t*)calloc(8, sizeof(uint8_t));
    uint8_t* t2 = (uint8_t*)calloc(8, sizeof(uint8_t));
    uint8_t tweak_difference = (uint8_t)(rand() % 256);

    for (int c = 0; c < 8; c++) {
            t1[c] = (uint8_t)(rand() % 256);
    }
  
    for (int c = 0; c < 8; c++) {
            t2[c] = t1[c];
    }
    t2[2*column+byte_number] = t1[2*column+byte_number] ^ tweak_difference;

    uint8_t* tweak1 = (uint8_t*)calloc(16, sizeof(uint8_t));
    uint8_t* tweak2 = (uint8_t*)calloc(16, sizeof(uint8_t));

    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 2; r++) {
            tweak1[c*4+r] = t1[c*2+r];
            tweak2[c*4+r] = t2[c*2+r]; 
        }
    }

    uint8_t* base_c = malloc(16);
    for (int i = 0; i < 16; i++) {
            base_c[i] = (uint8_t)(rand() % 256);
    }

    uint8_t possible_t1_values[256][16];
    uint8_t possible_t2_values[256][16];


    // compute with tweak 1
    for (int possible_c1_value = 0; possible_c1_value < 256; possible_c1_value++) {
        uint8_t* c1_tilde = malloc(16);
        for (int i = 0; i < 16; i++) {
            c1_tilde[i] = base_c[i];
        }
        c1_tilde[4*column+byte_number] = (uint8_t)possible_c1_value;

        shift_rows(c1_tilde);
        mixColumns(c1_tilde);
        add(c1_tilde, tweak1);
        compute_sibling(c1_tilde, key, t1, start_side);
        add(c1_tilde, tweak1);
        inverseMixedColumn(c1_tilde);
        inv_shift_rows(c1_tilde);
        
        for (int i = 0; i < 16; i++) {
            possible_t1_values[possible_c1_value][i] = c1_tilde[i];
        }
        
        free(c1_tilde);

    }

    // compute with tweak 2
    for (int possible_c1_value = 0; possible_c1_value < 256; possible_c1_value++) {
        uint8_t* c1_tilde = malloc(16);
        for (int i = 0; i < 16; i++) {
            c1_tilde[i] = base_c[i];
        }
        c1_tilde[4*column+byte_number] = (uint8_t)possible_c1_value;

        shift_rows(c1_tilde);
        mixColumns(c1_tilde);
        add(c1_tilde, tweak2);
        compute_sibling(c1_tilde, key, t2, start_side);
        add(c1_tilde, tweak2);
        inverseMixedColumn(c1_tilde);
        inv_shift_rows(c1_tilde);
        
        for (int i = 0; i < 16; i++) {
            possible_t2_values[possible_c1_value][i] = c1_tilde[i];
        }
        
        free(c1_tilde);
    }

    // FINDING A RIGHT COUPLE IN ORDER TO FIND THE KEY BYTE
    int indext1 = -1;
    int indext2 = -1;
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
            indext1 = -1;
            indext2 = -1;

            int result = 1;
            for (int byte = 0; byte < 16; byte++) {
                if (byte != 4*column+byte_number) {
                    if ((possible_t1_values[i][byte]^possible_t2_values[j][byte]) > 0) {
                        result = 0;
                        break;
                    }
                }
            }
                
            if (result == 1) {
                result = 0;
                for (int poss = 0; poss < 127; poss++) {
                    if ((possible_t1_values[i][4*column+byte_number]^possible_t2_values[j][4*column+byte_number]) == out_diff_for_tweak[(int)tweak_difference-1][poss]) {
                        result = 1;
                        break;
                    } 
                }

                if (result == 1) {
                    indext1 = i;
                    indext2 = j;
                    break;
                }                
            }           
        }
    }


    if (indext1 > -1 && indext2 > -1) {

        // printing the two ciphertexts C0_tilde
        //temporary for debugging
        uint8_t t11[16];
        uint8_t t21[16];
        for (int k = 0; k < 16; k++) {
            t11[k] = possible_t1_values[indext1][k];
            t21[k] = possible_t2_values[indext2][k];
        }
    

        shift_rows(t11);
        shift_rows(t21);
        
        mixColumns(t21);
        mixColumns(t11);
        


        pthread_t thread_ids[CORES];
        int cores = CORES;
        for (int bb = 0; bb < cores; bb++) {
            struct arg_struct args;
            args.exp = EXP;
            args.index = bb;
            args.t1 = possible_t1_values[indext1];
            args.t2 = possible_t2_values[indext2];
            args.tweak1 = tweak1;
            args.tweak2 = tweak2;
            args.column = column;
            args.byte_number = byte_number;
            args.key_number = key_number;

            pthread_create(&thread_ids[bb], NULL, attack_byte_thread, (void*)&args);
             
            nanosleep(&ts, &ts);
            
        }            
        
        for (int bb = 0; bb < cores; bb++) {
                pthread_join(thread_ids[bb], NULL);
        }      
    }

    free(tweak1);
    free(tweak2);
    free(base_c);
}


void compute_possibilities_for_key(int* number_of_keys) {
    int possibilities_for_byte[16];
    uint8_t* values_for_byte[16];
    int max_for_byte[16];

    //initialization
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 2; j++) {
            values_for_byte[j+i*4] = (uint8_t*) malloc(1*sizeof(uint8_t));
        }
    }
   
    for (int column = 0; column < 4; column++) {
        for (int byte_index = 0; byte_index < 2; byte_index++) {
            int j = byte_index + 4*column;

            int counter = 0;
            int max = 0;
            for (int i = 0; i < 256; i++) {
                if (key_bytes_possibilities_counter[j][i] > max) {
                    max = key_bytes_possibilities_counter[j][i];
                }
            }

            if (max > 0) {
                
                for (int i = 0; i < 256; i++) {
                    if (key_bytes_possibilities_counter[j][i] == max) {
                        counter++;
                        values_for_byte[j] = (uint8_t*) realloc(values_for_byte[j], counter*sizeof(uint8_t));
                        values_for_byte[j][counter-1] = i;
                    }
                }
            }
            possibilities_for_byte[j] = counter;
            printf("%d\n", counter);
            max_for_byte[j] = max;
        }
    }
   

    int column_possibilities[4];


    for (int i = 0; i < 4; i++) {
        column_possibilities[i] = possibilities_for_byte[0+4*i]*possibilities_for_byte[1+4*i];
    }


    for (int col = 0; col < 4; col++) {
        printf("Column: %d\n", col);
        for (int i1 = 0; i1 < possibilities_for_byte[0+4*col]; i1++) {
            for (int i2 = 0; i2 < possibilities_for_byte[1+4*col]; i2++) {
                printf("%d %d\n", values_for_byte[0+4*col][i1], values_for_byte[1+4*col][i2]);
            }
        }
    }


    printf("|    |    |    |    |\n");
    printf("|%4d|%4d|%4d|%4d|\n", column_possibilities[0], column_possibilities[1], column_possibilities[2], column_possibilities[3]);
    printf("|    |    |    |    |\n");
    printf("|    |    |    |    |\n");

    int possible_keys = (int)(column_possibilities[0]*column_possibilities[1]*column_possibilities[2]*column_possibilities[3]);
    printf("All the possible keys are: %d\n", possible_keys);

    *number_of_keys = possible_keys;

    for (int i = 0; i < 16; i++) {
        free(values_for_byte[i]);
    }
}

void compute_values_for_key(uint8_t** key_values) {
    int possibilities_for_byte[16];
    uint8_t* values_for_byte[16];
    int max_for_byte[16];

    //initialization
    for (int i = 0; i < 16; i++) {
        values_for_byte[i] = (uint8_t*) malloc(1*sizeof(uint8_t));
    }

    for (int j = 0; j < 16; j++) {
        int counter = 0;
        
        int max = 0;
        for (int i = 0; i < 256; i++) {
            if (key_bytes_possibilities_counter[j][i] > max) {
                max = key_bytes_possibilities_counter[j][i];
            }
        }

        if (max > 0) {
            
            for (int i = 0; i < 256; i++) {
                if (key_bytes_possibilities_counter[j][i] == max) {
                    counter++;
                    values_for_byte[j] = (uint8_t*) realloc(values_for_byte[j], counter*sizeof(uint8_t));
                    values_for_byte[j][counter-1] = i;
                }
            }
        }
        possibilities_for_byte[j] = counter;
        max_for_byte[j] = max;
    }

    uint8_t column_possibilities[4];


    for (int i = 0; i < 4; i++) {
        column_possibilities[i] = possibilities_for_byte[0+4*i]*possibilities_for_byte[1+4*i]*possibilities_for_byte[2+4*i]*possibilities_for_byte[3+4*i];
    }


    for (int col = 0; col < 4; col++) {

    }


    int possible_keys = (int)(column_possibilities[0]*column_possibilities[1]*column_possibilities[2]*column_possibilities[3]);
    
    int* column_values[4];
    for (int i = 0; i < 4; i++) {
        column_values[i] = (int*) malloc(column_possibilities[i]*sizeof(int));
    }

    for (int c = 0; c < 4; c++) {
        int index_poss = 0;
        for (int i = 0; i < possibilities_for_byte[0+4*c]; i++) {
            uint8_t byte0 = values_for_byte[0+4*c][i];
            for (int j = 0; j < possibilities_for_byte[1+4*c]; j++) {
                uint8_t byte1 = values_for_byte[1+4*c][j];
                for (int z = 0; z < possibilities_for_byte[2+4*c]; z++) {
                    uint8_t byte2 = values_for_byte[2+4*c][z];
                    for (int q = 0; q < possibilities_for_byte[3+4*c]; q++) {
                        uint8_t byte3 = values_for_byte[3+4*c][q];
                        int value = (byte0<<24) ^ (byte1<<16) ^ (byte2<<8) ^ (byte3<<0);
                        column_values[c][index_poss] = value;
                        index_poss++;
                    }
                }
            }
        }
    }

    

    int index_keys = 0;
    for (int c0 = 0; c0 < column_possibilities[0]; c0++) {
        for (int c1 = 0; c1 < column_possibilities[1]; c1++) {
            for (int c2 = 0; c2 < column_possibilities[2]; c2++) {
                for (int c3 = 0; c3 < column_possibilities[3]; c3++) {
                    //column0
                    key_values[index_keys][0] = (uint8_t)((column_values[0][c0] >> 24) & 0xFF);
                    key_values[index_keys][1] = (uint8_t)((column_values[0][c0] >> 16) & 0xFF);
                    key_values[index_keys][2] = (uint8_t)((column_values[0][c0] >> 8) & 0xFF);
                    key_values[index_keys][3] = (uint8_t)((column_values[0][c0] >> 0) & 0xFF);

                    //column1
                    key_values[index_keys][4] = (uint8_t)((column_values[1][c1] >> 24) & 0xFF);
                    key_values[index_keys][5] = (uint8_t)((column_values[1][c1] >> 16) & 0xFF);
                    key_values[index_keys][6] = (uint8_t)((column_values[1][c1] >> 8) & 0xFF);
                    key_values[index_keys][7] = (uint8_t)((column_values[1][c1] >> 0) & 0xFF);

                    //column0
                    key_values[index_keys][8] = (uint8_t)((column_values[2][c2] >> 24) & 0xFF);
                    key_values[index_keys][9] = (uint8_t)((column_values[2][c2] >> 16) & 0xFF);
                    key_values[index_keys][10] = (uint8_t)((column_values[2][c2] >> 8) & 0xFF);
                    key_values[index_keys][11] = (uint8_t)((column_values[2][c2] >> 0) & 0xFF);

                    //column0
                    key_values[index_keys][12] = (uint8_t)((column_values[3][c3] >> 24) & 0xFF);
                    key_values[index_keys][13] = (uint8_t)((column_values[3][c3] >> 16) & 0xFF);
                    key_values[index_keys][14] = (uint8_t)((column_values[3][c3] >> 8) & 0xFF);
                    key_values[index_keys][15] = (uint8_t)((column_values[3][c3] >> 0) & 0xFF);

                    index_keys++;
                }
            }
        }
    }

    for (int i = 0; i < 16; i++) {
        free(values_for_byte[i]);
    }
    for (int i = 0; i < 4; i++) {
        free(column_values[i]);
    }
    
}




int main(int argc, char** argv) {
    // initializing the key
    srand(time(NULL));   
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }

    // priting the keys to be found
    uint8_t round_keys[(HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2)*16];
    KeyExpansion(round_keys, key, HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS);

    printf("[****] Key List to find:\n");
    for (int i = 0; i < 10; i++) {
        printf("[K%d]: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%x ", round_keys[i*16+j]);
        }
        printf("\n");
    }



    // // keys reversed
    // for (int key_index = 0; key_index < (HEADER_ROUNDS+LEFT_ROUNDS+RIGHT_ROUNDS+2); key_index++) {
    //     uint8_t* k6 = malloc(16);

    //     for (int i = 0; i < 16; i++) {
    //         k6[i] = round_keys[16*key_index+i];
    //     }

        
    //     inverseMixedColumn(k6);
    //     //inv_shift_rows(k6);

    //     for (int i = 0; i < 16; i++) {
    //         printf("%x ", k6[i]);
    //     }
    //             printf("\n"); 

    //     free(k6);
    // }


    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 256; j++) {
            key_bytes_possibilities_counter[i][j] = 0;
        }
    }   


    
    printf("\n[+] Starting attack ...\n");
    printf("[Main] Finding K7\n");

    printf("[+] Finding first column possibilities\n");
    attack_byte(0, 0, 1, 7);
    attack_byte(0, 1, 1, 7);
    //attack_byte(0, 2, 1, 7);
    //attack_byte(0, 3, 1, 7);

    printf("[+] Finding second column possibilities\n");
    attack_byte(1, 0, 1, 7);
    attack_byte(1, 1, 1, 7);
    //attack_byte(1, 2, 1, 7);
    //attack_byte(1, 3, 1, 7);

    printf("[+] Finding third column possibilities\n");
    attack_byte(2, 0, 1, 7);
    attack_byte(2, 1, 1, 7);
    // attack_byte(2, 2, 1, 7);
    // attack_byte(2, 3, 1, 7);

    printf("[+] Finding fourth column possibilities\n");
    attack_byte(3, 0, 1, 7);
    attack_byte(3, 1, 1, 7);
    // attack_byte(3, 2, 1, 7);
    // attack_byte(3, 3, 1, 7);

    int number_of_keys = 0;
    compute_possibilities_for_key(&number_of_keys);

    printf("The remaining bytes should be bruteforced as explained in the document.\n");
    printf("Compute couples and validate keys after having solved the related system involving sbox.\n");

    // uint8_t** key_values = (uint8_t**) realloc(key_values, number_of_keys*sizeof(uint8_t*));
    // for (int i = 0; i < number_of_keys; i++) {
    //     key_values[i] = (uint8_t*) malloc(16*sizeof(uint8_t));
    // }
    
    // // generate all the possibilities for K7
    // compute_values_for_key(key_values);

    // // try to find k7 uniquely
    // uint8_t* k7 = (uint8_t*) malloc(16*sizeof(uint8_t));

    // find_intermediate_key_solution(key_values, number_of_keys, k7);
    // shift_rows(k7);
    // mixColumns(k7);
    // printf("[+] K7 was FOUND\n");

    // uint8_t* round_keys_derived = (uint8_t*) malloc((16*11)*sizeof(uint8_t));
    // KeyExpansion_from_intermediate_key(round_keys_derived, k7, 7, 9);
    
    // // PRINTING KEYS
    // for (int i = 0; i<10; i++) {
    //     printf("\nK%d: ", i);
    //     for (int j = 0; j < 16; j++) {
    //         printf("%x ",round_keys_derived[16*i+j]); // a copy of the key - this is k8
    //     }
        
    // }
    // printf("\n");


    
    /*
    * VALIDATING THE KEYS
    */ 
    // printf("[-] Validating Keys ...\n");
    // uint8_t* k0 = (uint8_t*) malloc(16*sizeof(uint8_t));
    // for (int i = 0; i < 16; i++) {
    //     k0[i] = round_keys_derived[i];
    // }

    // uint8_t* random_plaintext = (uint8_t*) malloc(16*sizeof(uint8_t));
    // uint8_t* text = (uint8_t*) malloc(16*sizeof(uint8_t));
    // uint8_t* tweak = (uint8_t*) malloc(16*sizeof(uint8_t));
    // uint8_t* c0 = (uint8_t*) malloc(16*sizeof(uint8_t));
    // uint8_t* c1 = (uint8_t*) malloc(16*sizeof(uint8_t));


    // srand(time(NULL));   
    // for (int i = 0; i < 16; i++) {
    //     random_plaintext[i] = (uint8_t)(rand() % 256);
    //     text[i] = random_plaintext[i];
    // }
    // for (int i = 0; i < 16; i++) {
    //     tweak[i] = (uint8_t)(rand() % 256);
    // }


    // encrypt(text, key, tweak, c0, c1);
    // decrypt(c0, k0, tweak, 0);
    // decrypt(c1, k0, tweak, 1);

    // int comparison = 1;

    // /*
    // * FORMULA
    // */
    // if (memcmp(c0, random_plaintext, 16) == 0 && memcmp(c1, random_plaintext, 16) == 0) {
    //     printf("[+] CORRECT KEY FOUND\n");
    // } 
    


    // free(random_plaintext);
    // free(text);
    // free(tweak);
    // free(c0);
    // free(c1);
    // free(k0);


    return 0;
}