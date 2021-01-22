#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "aes.h"

int main(){ 

	FILE* key_file            = fopen("cipher_key_128.bin", "r+b");
	FILE* plain_text_file     = fopen("plain_text.bin", "r+b");

	FILE* cipher_text_file    = fopen("cipher_text.bin", "w+b");
	FILE* plain_text_file_out = fopen("plain_text_out.bin", "w+b");
	
	AES_Encrypt(plain_text_file, cipher_text_file, key_file);

	fseek(cipher_text_file, 0, SEEK_SET);
	fseek(key_file, 0, SEEK_SET);

	AES_Decrypt(cipher_text_file, plain_text_file_out, key_file);

	return 0;
}

/****************   AUX   ****************/

// Galois Field (256) Multiplication of two Bytes
uint8_t GMul(uint8_t a, uint8_t b) { 

    uint8_t p = 0;

    for (int i = 0; i < 8; i++){

        if ((b & 1) != 0) {
            p ^= a;
        }


        uint8_t hi_bit_set = (a & 0x80) != 0;
        a <<= 1;

        if (hi_bit_set) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return p;
}

uint8_t* load_block(FILE* file){
	uint8_t* block = malloc(16);

	fread(block, 1, 16, file);

	return block;
}

uint8_t** format_block_1D_to_2D(uint8_t* block){
	uint8_t** formatted_block = malloc(4 * sizeof(uint8_t*));
	for (int i = 0; i < 4; ++i){
		formatted_block[i] = malloc(4);
	}

	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			formatted_block[i][j] = block[4 * i + j];
		}
	}

	return formatted_block;
}

uint8_t* format_block_2D_to_1D(uint8_t** formatted_block){
	uint8_t* block = malloc(16);

	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			block[4 * i + j] = formatted_block[i][j];
		}
	}

	return block;
}

uint8_t*** init_round_key(){

	uint8_t ***round_key = malloc(11 * sizeof(uint8_t**));
	
	for (int round = 0; round < 11; round++){
		round_key[round] = malloc(4 * sizeof(uint8_t*));

		for (int line = 0; line < 4; line++){
			round_key[round][line] = malloc(4);
		}
	}

	return round_key;
}

int get_size(FILE* file){
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	return size;
}

/**************** END AUX ****************/

void KeyExpansion(uint8_t ***round_key, uint8_t** key){

	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			round_key[0][i][j] = key[i][j];
		}
	}
	
	for (int i = 1; i <= 10; ++i){
		uint8_t s_0 = round_key[i-1][1][3];
		uint8_t s_1 = round_key[i-1][2][3];
		uint8_t s_2 = round_key[i-1][3][3];
		uint8_t s_3 = round_key[i-1][0][3];

		s_0 = sbox[s_0];
		s_1 = sbox[s_1];
		s_2 = sbox[s_2];
		s_3 = sbox[s_3];

		round_key[i][0][0] = round_key[i-1][0][0] ^ s_0 ^ rcon[i-1];
		round_key[i][1][0] = round_key[i-1][1][0] ^ s_1;
		round_key[i][2][0] = round_key[i-1][2][0] ^ s_2;
		round_key[i][3][0] = round_key[i-1][3][0] ^ s_3;

		for (int j = 1; j < 4; j++){
			round_key[i][0][j] = round_key[i][0][j-1] ^ round_key[i-1][0][j];
			round_key[i][1][j] = round_key[i][1][j-1] ^ round_key[i-1][1][j];
			round_key[i][2][j] = round_key[i][2][j-1] ^ round_key[i-1][2][j];
			round_key[i][3][j] = round_key[i][3][j-1] ^ round_key[i-1][3][j];
		}
	}
}

void addRoundKey(int round, uint8_t** state, uint8_t ***round_key){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			state[i][j] ^= round_key[round][i][j];
		}
	}
}

void SubBytes(uint8_t** state){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			state[i][j] = sbox[state[i][j]];
		}
	}
}

void InvSubBytes(uint8_t** state){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			state[i][j] = rsbox[state[i][j]];
		}
	}
}

void ShiftRows(uint8_t** state){

	uint8_t tmp_0, tmp_1, tmp_2;

	tmp_0 = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = tmp_0;

	tmp_0 = state[2][0];
	tmp_1 = state[2][1];
	state[2][0] = state[2][2];
	state[2][1] = state[2][3];
	state[2][2] = tmp_0;
	state[2][3] = tmp_1;

	tmp_0 = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = tmp_0;

}

void InvShiftRows(uint8_t** state){

	uint8_t tmp_0, tmp_1, tmp_2;

	tmp_0 = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = tmp_0;

	tmp_0 = state[2][0];
	tmp_1 = state[2][1];
	state[2][0] = state[2][2];
	state[2][1] = state[2][3];
	state[2][2] = tmp_0;
	state[2][3] = tmp_1;

	tmp_0 = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = tmp_0;

}

void MixColumns(uint8_t** state){

	for (int j = 0; j < 4; j++){

		uint8_t s_0 = GMul(0x02, state[0][j]) ^ GMul(0x03, state[1][j]) ^ GMul(0x01, state[2][j]) ^ GMul(0x01, state[3][j]);
		uint8_t s_1 = GMul(0x01, state[0][j]) ^ GMul(0x02, state[1][j]) ^ GMul(0x03, state[2][j]) ^ GMul(0x01, state[3][j]);
		uint8_t s_2 = GMul(0x01, state[0][j]) ^ GMul(0x01, state[1][j]) ^ GMul(0x02, state[2][j]) ^ GMul(0x03, state[3][j]);
		uint8_t s_3 = GMul(0x03, state[0][j]) ^ GMul(0x01, state[1][j]) ^ GMul(0x01, state[2][j]) ^ GMul(0x02, state[3][j]);

		state[0][j] = s_0;
		state[1][j] = s_1;
		state[2][j] = s_2;
		state[3][j] = s_3;
	}

}

void InvMixColumns(uint8_t** state){

	for (int j = 0; j < 4; j++){

		uint8_t s_0 = GMul(0x0e, state[0][j]) ^ GMul(0x0b, state[1][j]) ^ GMul(0x0d, state[2][j]) ^ GMul(0x09, state[3][j]);
		uint8_t s_1 = GMul(0x09, state[0][j]) ^ GMul(0x0e, state[1][j]) ^ GMul(0x0b, state[2][j]) ^ GMul(0x0d, state[3][j]);
		uint8_t s_2 = GMul(0x0d, state[0][j]) ^ GMul(0x09, state[1][j]) ^ GMul(0x0e, state[2][j]) ^ GMul(0x0b, state[3][j]);
		uint8_t s_3 = GMul(0x0b, state[0][j]) ^ GMul(0x0d, state[1][j]) ^ GMul(0x09, state[2][j]) ^ GMul(0x0e, state[3][j]);

		state[0][j] = s_0;
		state[1][j] = s_1;
		state[2][j] = s_2;
		state[3][j] = s_3;
	}

}

void AES_Encrypt_block(uint8_t** state, uint8_t*** round_key){
	addRoundKey(0, state, round_key);

	for (int i = 1; i < 10; ++i){
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		addRoundKey(i, state, round_key);	
	}

	SubBytes(state);
	ShiftRows(state);

	addRoundKey(10, state, round_key);
}

void AES_Decrypt_block(uint8_t** state, uint8_t*** round_key){
	addRoundKey(10, state, round_key);

	for (int i = 9; i > 0; i--){
		InvShiftRows(state);
		InvSubBytes(state);
		addRoundKey(i, state, round_key);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);

	addRoundKey(0, state, round_key);
}

void AES_Encrypt(FILE* file, FILE* out, FILE* key_file){
	int file_size = get_size(file);

	uint8_t*** round_key = init_round_key();
	uint8_t** key        = format_block_1D_to_2D(load_block(key_file));
	KeyExpansion(round_key, key);

	for (int i = 0, padded = 0; padded != 1; i += 16){

		uint8_t* block;

		if(i > file_size){
			block = malloc(16);

			for (int j = 0; j < 16; j++){
				block[j] = 16;
			}

			padded = 1; 
		}else if(file_size - i < 16){
			
			block = malloc(16);
			fread(block, 1, file_size - i, file);

			for (int j = file_size - i; j < 16; j++){
				block[j] = 16 - (file_size - i);
			}

			padded = 1; 

		}else {
			block = load_block(file);
		}
		
		uint8_t** formated_block = format_block_1D_to_2D(block);
		
		AES_Encrypt_block(formated_block, round_key);

		block = format_block_2D_to_1D(formated_block);

		fwrite(block, 1, 16, out);
	}

}

void AES_Decrypt(FILE* file, FILE* out, FILE* key_file){
	int file_size = get_size(file);

	uint8_t ***round_key = init_round_key();
	uint8_t** key        = format_block_1D_to_2D(load_block(key_file));
	
	KeyExpansion(round_key, key);

	for (int i = 0; i < file_size; i += 16){
		uint8_t* block           = load_block(file);
		uint8_t** formated_block = format_block_1D_to_2D(block);
		
		AES_Decrypt_block(formated_block, round_key);

		block = format_block_2D_to_1D(formated_block);

		if(file_size - i == 16){
			fwrite(block, 1, 16 - block[15], out);
		}else {
			fwrite(block, 1, 16, out);
		}

		
	}

}
