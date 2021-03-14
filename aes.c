#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "aux.h"

void KeyExpansion(uint8_t **round_key, uint8_t** key){

	for (int i = 0; i < 4; i++){
		for (int j = 0; j < nk; j++){
			round_key[i][j] = key[i][j];
		}
	}

	for (int i = nk; i < 4 * (nr + 1); i++){

		round_key[0][i] = round_key[0][i-1];
		round_key[1][i] = round_key[1][i-1];
		round_key[2][i] = round_key[2][i-1];
		round_key[3][i] = round_key[3][i-1];

		if(i % nk == 0){

			uint8_t s_0 = sbox[round_key[1][i]];
			uint8_t s_1 = sbox[round_key[2][i]];
			uint8_t s_2 = sbox[round_key[3][i]];
			uint8_t s_3 = sbox[round_key[0][i]];

			round_key[0][i] = s_0 ^ rcon[i/nk];
			round_key[1][i] = s_1;
			round_key[2][i] = s_2;
			round_key[3][i] = s_3;

		}else if(nk > 6 && i % nk == 4){

			round_key[0][i] = sbox[round_key[0][i-1]];
			round_key[1][i] = sbox[round_key[1][i-1]];
			round_key[2][i] = sbox[round_key[2][i-1]];
			round_key[3][i] = sbox[round_key[3][i-1]];

		}

		round_key[0][i] ^= round_key[0][i-nk];
		round_key[1][i] ^= round_key[1][i-nk];
		round_key[2][i] ^= round_key[2][i-nk];
		round_key[3][i] ^= round_key[3][i-nk];
		
	}
}

void addRoundKey(int round, uint8_t** state, uint8_t **round_key){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			state[i][j] ^= round_key[i][j+(round*4)];
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

		uint8_t s_0 = gmul(0x02, state[0][j]) ^ gmul(0x03, state[1][j]) ^ gmul(0x01, state[2][j]) ^ gmul(0x01, state[3][j]);
		uint8_t s_1 = gmul(0x01, state[0][j]) ^ gmul(0x02, state[1][j]) ^ gmul(0x03, state[2][j]) ^ gmul(0x01, state[3][j]);
		uint8_t s_2 = gmul(0x01, state[0][j]) ^ gmul(0x01, state[1][j]) ^ gmul(0x02, state[2][j]) ^ gmul(0x03, state[3][j]);
		uint8_t s_3 = gmul(0x03, state[0][j]) ^ gmul(0x01, state[1][j]) ^ gmul(0x01, state[2][j]) ^ gmul(0x02, state[3][j]);

		state[0][j] = s_0;
		state[1][j] = s_1;
		state[2][j] = s_2;
		state[3][j] = s_3;
	}

}

void InvMixColumns(uint8_t** state){

	for (int j = 0; j < 4; j++){

		uint8_t s_0 = gmul(0x0e, state[0][j]) ^ gmul(0x0b, state[1][j]) ^ gmul(0x0d, state[2][j]) ^ gmul(0x09, state[3][j]);
		uint8_t s_1 = gmul(0x09, state[0][j]) ^ gmul(0x0e, state[1][j]) ^ gmul(0x0b, state[2][j]) ^ gmul(0x0d, state[3][j]);
		uint8_t s_2 = gmul(0x0d, state[0][j]) ^ gmul(0x09, state[1][j]) ^ gmul(0x0e, state[2][j]) ^ gmul(0x0b, state[3][j]);
		uint8_t s_3 = gmul(0x0b, state[0][j]) ^ gmul(0x0d, state[1][j]) ^ gmul(0x09, state[2][j]) ^ gmul(0x0e, state[3][j]);

		state[0][j] = s_0;
		state[1][j] = s_1;
		state[2][j] = s_2;
		state[3][j] = s_3;
	}

}

void AES_Encrypt_block(uint8_t** state, uint8_t** round_key){
	addRoundKey(0, state, round_key);

	for (int i = 1; i < nr; ++i){
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		addRoundKey(i, state, round_key);	
	}

	SubBytes(state);
	ShiftRows(state);

	addRoundKey(nr, state, round_key);
}

void AES_Decrypt_block(uint8_t** state, uint8_t** round_key){
	addRoundKey(nr, state, round_key);

	for (int i = nr - 1; i > 0; i--){
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
	
	uint8_t **key       = block_1D_to_2D(load_block(key_file, nk * 4, nk * 4), 4, nk);
	uint8_t **round_key = init_round_key();

	KeyExpansion(round_key, key);

	for (int i = 0; i <= file_size; i += 16){

		uint8_t* block;

		/* ADD PADDING*/
		if(i == file_size){
			
			block = load_block(file, 16, 0);
			add_padding(block, 0X10);

		}else if(file_size - i < 16){

			block = load_block(file, 16, file_size - i);
			add_padding(block, 0X10 - (file_size - i));

		}else {
			block = load_block(file, 16, 16);
		}
		/* ADD PADDING*/
		
		uint8_t** formated_block = block_1D_to_2D(block, 4, 4);
		
		AES_Encrypt_block(formated_block, round_key);

		block = block_2D_to_1D(formated_block, 4, 4);

		fwrite(block, 1, 16, out);
	}

	fseek(file, 0, SEEK_SET);
	fseek(key_file, 0, SEEK_SET);

}

void AES_Decrypt(FILE* file, FILE* out, FILE* key_file){
	int file_size = get_size(file);

	uint8_t **round_key = init_round_key();
	uint8_t** key        = block_1D_to_2D(load_block(key_file, nk * 4,nk * 4), 4, nk);
	
	KeyExpansion(round_key, key);

	for (int i = 0; i < file_size; i += 16){
		uint8_t* block           = load_block(file, 16, 16);
		uint8_t** formated_block = block_1D_to_2D(block, 4, 4);

		AES_Decrypt_block(formated_block, round_key);

		block = block_2D_to_1D(formated_block, 4, 4);

		/* REMOVING PADDING*/
		
		if(file_size - i == 16){
			fwrite(block, 1, 16 - block[15], out);
		}else {
			fwrite(block, 1, 16, out);
		}

		/* REMOVING PADDING*/

	}

	fseek(file, 0, SEEK_SET);
	fseek(key_file, 0, SEEK_SET);
}
