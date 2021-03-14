#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "aux.h"

uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t p = 0;
	uint8_t hi_bit_set;

	for(uint8_t i = 0; i < 8; i++) {
		if((b & 1) == 1) 
			p ^= a;

		hi_bit_set = a & 0x80;
		a <<= 1;

		if(hi_bit_set == 0x80) 
			a ^= 0x1b;	

		b >>= 1;
	}

	return p;
}

uint8_t* load_block(FILE* file, uint8_t size, uint8_t count){
	uint8_t* block = malloc(size);
	fread(block, 1, count, file);
	return block;
}

uint8_t** block_1D_to_2D(uint8_t* block, int y, int x){
	uint8_t** formatted_block = malloc(y * sizeof(uint8_t*));
	for (int i = 0; i < y; ++i){
		formatted_block[i] = malloc(x);
	}

	for (int i = 0; i < y; i++){
		for (int j = 0; j < x; j++){
			formatted_block[i][j] = block[(x * i) + j];
		}
	}

	return formatted_block;
}

uint8_t* block_2D_to_1D(uint8_t** formatted_block, int y, int x){
	uint8_t* block = malloc(y * x);

	for (int i = 0; i < y; i++){
		for (int j = 0; j < x; j++){
			block[(x * i) + j] = formatted_block[i][j];
		}
	}

	return block;
}

uint8_t** init_round_key(){

	uint8_t** round_key = malloc(4 * sizeof(uint8_t*));

	for (int i = 0; i < 4; ++i){
		round_key[i] = malloc(4 * (nr + 1));
		memset(round_key[i], 0, 4 * (nr + 1));
	}
	
	return round_key;
}

int get_size(FILE* file){
	fseek(file, 0, SEEK_END);
	int size = ftell(file);
	fseek(file, 0, SEEK_SET);
	return size;
}

void add_padding(uint8_t* block, uint8_t pad){
	for (int i = 16 - pad; i < 16; i++){
		block[i] = pad;
	}
}