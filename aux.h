#ifndef AUX_H_INCLUDED
#define AUX_H_INCLUDED

uint8_t gmul(uint8_t a, uint8_t b);

uint8_t* load_block(FILE* text, uint8_t size, uint8_t count);

uint8_t** block_1D_to_2D(uint8_t* block, int y, int x);

uint8_t* block_2D_to_1D(uint8_t** formatted_block, int y, int x);

uint8_t** init_round_key();

int get_size(FILE* file);

void add_padding(uint8_t* block, uint8_t pad);

#endif