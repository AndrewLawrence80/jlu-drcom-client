#include "logger.h"
#include "config.h"
#include "debug_utils.h"
#include <string.h>

void logger_init(Logger *logger_this)
{
    memset(logger_this->keep_alive_auth_send, 0, CONFIG_SIZE_KEEP_ALIVE_AUTH);
    memset(logger_this->keep_alive_heart_beat_send, 0, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);

    logger_this->time_keep_alive_auth_send = 0;
    logger_this->time_keep_alive_auth_receive = 0;
    logger_this->time_keep_alive_heart_beat_send = 0;
    logger_this->time_keep_alive_heart_beat_receive = 0;

    logger_this->count_keep_alive_auth_send = 0;
    logger_this->count_keep_alive_auth_receive = 0;
    logger_this->count_keep_alive_heart_beat_send = 0;
    logger_this->count_keep_alive_heart_beat_receive = 0;

    pthread_mutex_init(&(logger_this->mutex_keep_alive_auth_send), NULL);
    pthread_mutex_init(&(logger_this->mutex_keep_alive_auth_receive), NULL);
    pthread_mutex_init(&(logger_this->mutex_keep_alive_heart_beat_send), NULL);
    pthread_mutex_init(&(logger_this->mutex_keep_alive_heart_beat_receive), NULL);
}
void logger_log_challenge_send(unsigned char *buffer_send)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("send challenge msg to server", buffer_send, CONFIG_SIZE_CHALLENGE);
    }
}
void logger_log_challenge_receive(unsigned char *buffer_receive, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("receive challenge msg from server", buffer_receive, size);
        debug_msg("login salt", buffer_receive + 4, CONFIG_SIZE_SALT);
    }
}
void logger_log_auth_send(unsigned char *buffer_send, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("send auth msg to server", buffer_send, size);
    }
}
void logger_log_auth_receive(unsigned char *buffer_receive, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("receive auth msg from server", buffer_receive, size);
    }
}
void logger_log_keep_alive_auth_send(Logger *logger_this, unsigned char *buffer_send)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("send keep alive auth msg to server", buffer_send, CONFIG_SIZE_KEEP_ALIVE_AUTH);
    }
    logger_try_lock_mutex_keep_alive_auth_send(logger_this);
    memcpy(logger_this->keep_alive_auth_send, buffer_send, CONFIG_SIZE_KEEP_ALIVE_AUTH);
    logger_this->time_keep_alive_auth_send = time(NULL);
    ++(logger_this->count_keep_alive_auth_send);
    logger_unlock_mutex_keep_alive_auth_send(logger_this);
}
void logger_log_keep_alive_auth_receive(Logger *logger_this, unsigned char *buffer_receive, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("receive keep alive auth msg from server", buffer_receive, size);
    }
    logger_try_lock_mutex_keep_alive_auth_receive(logger_this);
    logger_this->time_keep_alive_auth_receive = time(NULL);
    ++(logger_this->count_keep_alive_auth_receive);
    logger_unlock_mutex_keep_alive_auth_receive(logger_this);
}
void logger_log_keep_alive_heart_beat_send(Logger *logger_this, unsigned char *buffer_send)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("send keep alive heart beat msg to server", buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
    }
    logger_try_lock_mutex_keep_alive_heart_beat_send(logger_this);
    memcpy(logger_this->keep_alive_heart_beat_send, buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
    logger_this->time_keep_alive_heart_beat_send = time(NULL);
    ++(logger_this->count_keep_alive_heart_beat_send);
    logger_unlock_mutex_keep_alive_heart_beat_send(logger_this);
}
void logger_log_keep_alive_heart_beat_receive(Logger *logger_this, unsigned char *buffer_receive, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("receive keep alive heart beat msg from server", buffer_receive, size);
    }
    logger_try_lock_mutex_keep_alive_heart_beat_receive(logger_this);
    logger_this->time_keep_alive_heart_beat_receive = time(NULL);
    ++(logger_this->count_keep_alive_heart_beat_receive);
    logger_unlock_mutex_keep_alive_heart_beat_receive(logger_this);
}
void logger_log_logout_send(unsigned char *buffer_send)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("send logout msg to server", buffer_send, CONFIG_SIZE_LOGOUT);
    }
}
void logger_log_logout_receive(unsigned char *buffer_receive, unsigned long size)
{
    if (CONFIG_DEBUG)
    {
        debug_msg("receive logout msg from server", buffer_receive, size);
    }
}

void logger_try_lock_mutex_keep_alive_auth_send(Logger *logger_this)
{
    pthread_mutex_trylock(&(logger_this->mutex_keep_alive_auth_send));
}
void logger_unlock_mutex_keep_alive_auth_send(Logger *logger_this)
{
    pthread_mutex_unlock(&(logger_this->mutex_keep_alive_auth_send));
}
void logger_try_lock_mutex_keep_alive_auth_receive(Logger *logger_this)
{
    pthread_mutex_trylock(&(logger_this->mutex_keep_alive_auth_receive));
}
void logger_unlock_mutex_keep_alive_auth_receive(Logger *logger_this)
{
    pthread_mutex_unlock(&(logger_this->mutex_keep_alive_auth_receive));
}
void logger_try_lock_mutex_keep_alive_heart_beat_send(Logger *logger_this)
{
    pthread_mutex_trylock(&(logger_this->mutex_keep_alive_heart_beat_send));
}
void logger_unlock_mutex_keep_alive_heart_beat_send(Logger *logger_this)
{
    pthread_mutex_unlock(&(logger_this->mutex_keep_alive_heart_beat_send));
}
void logger_try_lock_mutex_keep_alive_heart_beat_receive(Logger *logger_this)
{
    pthread_mutex_trylock(&(logger_this->mutex_keep_alive_heart_beat_receive));
}
void logger_unlock_mutex_keep_alive_heart_beat_receive(Logger *logger_this)
{
    pthread_mutex_unlock(&(logger_this->mutex_keep_alive_heart_beat_receive));
}
