#ifndef _LOGGER_H
#define _LOGGER_H
#include <pthread.h>
#include "config.h"

typedef struct
{
    unsigned char keep_alive_auth_send[CONFIG_SIZE_KEEP_ALIVE_AUTH];
    unsigned char keep_alive_heart_beat_send[CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT];

    long time_keep_alive_auth_send;
    long time_keep_alive_auth_receive;
    long time_keep_alive_heart_beat_send;
    long time_keep_alive_heart_beat_receive;

    unsigned long count_keep_alive_auth_send;
    unsigned long count_keep_alive_auth_receive;
    unsigned long count_keep_alive_heart_beat_send;
    unsigned long count_keep_alive_heart_beat_receive;

    pthread_mutex_t mutex_keep_alive_auth_send;
    pthread_mutex_t mutex_keep_alive_auth_receive;
    pthread_mutex_t mutex_keep_alive_heart_beat_send;
    pthread_mutex_t mutex_keep_alive_heart_beat_receive;
} Logger;

void logger_init(Logger *logger_this);
void logger_log_challenge_send(unsigned char *buffer_send);
void logger_log_challenge_receive(unsigned char *buffer_receive, unsigned long size);
void logger_log_auth_send(unsigned char *buffer_send, unsigned long size);
void logger_log_auth_receive(unsigned char *buffer_receive, unsigned long size);
void logger_log_keep_alive_auth_send(Logger *logger_this, unsigned char *buffer_send);
void logger_log_keep_alive_auth_receive(Logger *logger_this, unsigned char *buffer_receive, unsigned long size);
void logger_log_keep_alive_heart_beat_send(Logger *logger_this, unsigned char *buffer_send);
void logger_log_keep_alive_heart_beat_receive(Logger *logger_this, unsigned char *buffer_receive, unsigned long size);
void logger_log_logout_send(unsigned char *buffer_send);
void logger_log_logout_receive(unsigned char *buffer_receive, unsigned long size);
void logger_try_lock_mutex_keep_alive_auth_send(Logger *logger_this);
void logger_unlock_mutex_keep_alive_auth_send(Logger *logger_this);
void logger_try_lock_mutex_keep_alive_auth_receive(Logger *logger_this);
void logger_unlock_mutex_keep_alive_auth_receive(Logger *logger_this);
void logger_try_lock_mutex_keep_alive_heart_beat_send(Logger *logger_this);
void logger_unlock_mutex_keep_alive_heart_beat_send(Logger *logger_this);
void logger_try_lock_mutex_keep_alive_heart_beat_receive(Logger *logger_this);
void logger_unlock_mutex_keep_alive_heart_beat_receive(Logger *logger_this);

#endif