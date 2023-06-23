#include "resend.h"
#include "debug_utils.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
void resend_keep_alive_auth_check_and_resend(Client *client, Logger *logger)
{
    long time_keep_alive_auth_send = 0;
    long count_keep_alive_auth_send = 0;
    long count_keep_alive_auth_receive = 0;

    logger_try_lock_mutex_keep_alive_auth_send(logger);
    time_keep_alive_auth_send = logger->time_keep_alive_auth_send;
    count_keep_alive_auth_send = logger->count_keep_alive_auth_send;
    logger_unlock_mutex_keep_alive_auth_send(logger);

    logger_try_lock_mutex_keep_alive_auth_receive(logger);
    count_keep_alive_auth_receive = logger->count_keep_alive_auth_receive;
    logger_unlock_mutex_keep_alive_auth_receive(logger);

    if (CONFIG_DEBUG)
    {
        printf("count_keep_alive_auth_send = %ld\n", count_keep_alive_auth_send);
        printf("count_keep_alive_auth_receive = %ld\n", count_keep_alive_auth_receive);
    }

    int count_retry_keep_alive_auth = 0;
    while (count_keep_alive_auth_send > count_keep_alive_auth_receive && time(NULL) - time_keep_alive_auth_send > 2 && count_retry_keep_alive_auth < 3)
    {
        socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client->server_sockaddr);
        ssize_t size_send = -1;
        if (CONFIG_DEBUG)
        {
            debug_msg("resend keep alive auth to server", logger->keep_alive_auth_send, CONFIG_SIZE_KEEP_ALIVE_AUTH);
        }
        size_send = sendto(client->client_sockfd, logger->keep_alive_auth_send, CONFIG_SIZE_KEEP_ALIVE_AUTH, 0, (const struct sockaddr *)&(client->server_sockaddr), socklen_server_sockaddr);
        if (size_send < 0)
        {
            perror("error when resending to server during keep alive auth");
            exit(EXIT_FAILURE);
        }

        sleep(1);
        ++count_retry_keep_alive_auth;

        logger_try_lock_mutex_keep_alive_auth_send(logger);
        time_keep_alive_auth_send = logger->time_keep_alive_auth_send;
        count_keep_alive_auth_send = logger->count_keep_alive_auth_send;
        logger_unlock_mutex_keep_alive_auth_send(logger);

        logger_try_lock_mutex_keep_alive_auth_receive(logger);
        count_keep_alive_auth_receive = logger->count_keep_alive_auth_receive;
        logger_unlock_mutex_keep_alive_auth_receive(logger);
    }
    if (count_retry_keep_alive_auth == 3)
    {
        perror("error when resend keep alive auth: failed after max retry");
        exit(EXIT_FAILURE);
    }
}
void resend_keep_alive_heart_beat_check_and_resend(Client *client, Logger *logger)
{
    long time_keep_alive_heart_beat_send = 0;
    long count_keep_alive_heart_beat_send = 0;
    long count_keep_alive_heart_beat_receive = 0;

    logger_try_lock_mutex_keep_alive_heart_beat_send(logger);
    time_keep_alive_heart_beat_send = logger->time_keep_alive_heart_beat_send;
    count_keep_alive_heart_beat_send = logger->count_keep_alive_heart_beat_send;
    logger_unlock_mutex_keep_alive_heart_beat_send(logger);

    logger_try_lock_mutex_keep_alive_heart_beat_receive(logger);
    count_keep_alive_heart_beat_receive = logger->count_keep_alive_heart_beat_receive;
    logger_unlock_mutex_keep_alive_heart_beat_receive(logger);

    if (CONFIG_DEBUG)
    {
        printf("count_keep_alive_heart_beat_send = %ld\n", count_keep_alive_heart_beat_send);
        printf("count_keep_alive_heart_beat_receive = %ld\n", count_keep_alive_heart_beat_receive);
    }

    int count_retry_keep_alive_heart_beat = 0;
    while (count_keep_alive_heart_beat_send > count_keep_alive_heart_beat_receive && time(NULL) - time_keep_alive_heart_beat_send > 2 && count_retry_keep_alive_heart_beat < 3)
    {
        socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client->server_sockaddr);
        ssize_t size_send = -1;
        if (CONFIG_DEBUG)
        {
            debug_msg("resend keep alive heartbeat to server", logger->keep_alive_heart_beat_send,CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
        }
        size_send = sendto(client->client_sockfd, logger->keep_alive_heart_beat_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT, 0, (const struct sockaddr *)&(client->server_sockaddr), socklen_server_sockaddr);
        if (size_send < 0)
        {
            perror("error when resending keep alive heart beat to server");
            exit(EXIT_FAILURE);
        }

        sleep(1);
        ++count_retry_keep_alive_heart_beat;

        logger_try_lock_mutex_keep_alive_heart_beat_send(logger);
        time_keep_alive_heart_beat_send = logger->time_keep_alive_heart_beat_send;
        count_keep_alive_heart_beat_send = logger->count_keep_alive_heart_beat_send;
        logger_unlock_mutex_keep_alive_heart_beat_send(logger);

        logger_try_lock_mutex_keep_alive_heart_beat_receive(logger);
        count_keep_alive_heart_beat_receive = logger->count_keep_alive_heart_beat_receive;
        logger_unlock_mutex_keep_alive_heart_beat_receive(logger);
    }
    if (count_retry_keep_alive_heart_beat == 3)
    {
        perror("error when resend keep alive heart beat: failed after max retry");
        exit(EXIT_FAILURE);
    }
}
void *resend_run_keep_alive_auth_check_and_resend(void *args)
{
    ARG_Resend *arg_resend = (ARG_Resend *)args;
    long count_turn = 0;
    while (1)
    {
        if (CONFIG_DEBUG)
        {
            printf("count of keep alive auth at turn %ld\n", count_turn);
        }
        resend_keep_alive_auth_check_and_resend(arg_resend->client, arg_resend->logger);
        sleep(1);
        ++count_turn;
    }
}
void *resend_run_keep_alive_heart_beat_check_and_resend(void *args)
{
    ARG_Resend *arg_resend = (ARG_Resend *)args;
    long count_turn = 0;
    while (1)
    {
        if (CONFIG_DEBUG)
        {
            printf("count of keep alive heart beat at turn %ld\n", count_turn);
        }
        resend_keep_alive_heart_beat_check_and_resend(arg_resend->client, arg_resend->logger);
        sleep(1);
        ++count_turn;
    }
}