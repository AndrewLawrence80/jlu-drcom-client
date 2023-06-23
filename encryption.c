#include "encryption.h"

void encryption_gen_md5(const void *data, unsigned long size_input, unsigned char *result)
{
    MD5(data, size_input, result);
}
void encryption_gen_xor(unsigned char *data_a, unsigned char *data_b, unsigned long size_input, unsigned char *result, unsigned long size_output)
{
    unsigned long size = size_input > size_output ? size_output : size_input;
    for (unsigned long i = 0; i < size; ++i)
    {
        result[i] = data_a[i] ^ data_b[i];
    }
}
void encryption_gen_ror(unsigned char *data, unsigned long size, unsigned char *result)
{
    for (unsigned long i = 0; i < size; ++i)
    {
        result[i] = (unsigned char)((data[i] << 3 ) + (data[i] >> 5));
    }
}
void encryption_gen_checksum(unsigned char *data, unsigned long size_input, unsigned char *result, unsigned long size_output)
{
    unsigned long sum_checksum = 1234;
    for (unsigned long i = 0; i < size_input; i += 4)
    {
        unsigned long tmp = 0;
        for (int j = 4; j > 0; --j)
        {
            tmp *= 256;
            tmp += (unsigned long)data[i + j - 1];
        }
        sum_checksum ^= tmp;
    }
    sum_checksum = (1968 * sum_checksum) & 0xffffffff;
    for (unsigned long i = 0; i < size_output; ++i)
    {
        result[i] = (unsigned char)(sum_checksum >> (i * 8) & 0xff);
    }
}
void encryption_gen_crc(unsigned char *data, unsigned long size_input, unsigned char *result, unsigned long size_output)
{
    unsigned long sum_crc = 0;
    for (unsigned long i = 0; i < size_input; i += 2)
    {
        unsigned long tmp = 0;
        for (unsigned long j = 2; j > 0; --j)
        {
            tmp *= 2 << 7;
            tmp += (unsigned long)data[i + j - 1];
        }
        sum_crc ^= tmp;
    }
    sum_crc = (711 * sum_crc);
    for (unsigned long i = 0; i < size_output; ++i)
    {
        result[i] = (unsigned char)(sum_crc >> (i * 8) & 0xff);
    }
}