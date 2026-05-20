#ifndef _RESEND_H
#define _RESEND_H
#include "logger.h"
#include "client.h"
typedef struct
{
    Client *client;
    Logger *logger;
} ARG_Resend;

void resend_keep_alive_auth_check_and_resend(Client *client, Logger *logger);
void resend_keep_alive_heart_beat_check_and_resend(Client* client,Logger *logger);
void* resend_run_keep_alive_auth_check_and_resend(void *args);
void* resend_run_keep_alive_heart_beat_check_and_resend(void* args);
#endif