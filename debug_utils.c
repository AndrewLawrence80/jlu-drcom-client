#include "debug_utils.h"
#include <stdio.h>
void debug_msg(const char *msg, unsigned char *buffer, unsigned long size)
{
    printf("%s\n", msg);
    if (buffer)
    {
        for (unsigned long i = 0; i < size; ++i)
        {
            printf("%02x", buffer[i]);
            if ((i + 1) % 16 == 0)
            {
                printf("\n");
            }
            else
            {
                if ((i + 1) % 8 == 0)
                {
                    printf("    ");
                }
                else
                {
                    printf(" ");
                }
            }
        }
        printf("\n");
    }
}