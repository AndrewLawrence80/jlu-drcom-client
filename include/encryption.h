#ifndef _ENCRYPTION_H
#define _ENCRYPTION_H
#include "md5.h"

// output is 16 bit by default
void encryption_gen_md5(const void *data, unsigned long size_input, unsigned char *result);
// data_a ^ data_b
void encryption_gen_xor(unsigned char *data_a, unsigned char *data_b, unsigned long size_input, unsigned char *result, unsigned long size_output);
// ror for JLU login
void encryption_gen_ror(unsigned char *data, unsigned long size, unsigned char *result);
// checksum for JLU login
// size % 4 == 0, 344 default for JLU
void encryption_gen_checksum(unsigned char *data, unsigned long size_input, unsigned char *result, unsigned long size_output);
// crc for JLU keep alive
void encryption_gen_crc(unsigned char *data, unsigned long size_input, unsigned char *result, unsigned long size_output);
#endif