#include "config.h"
#include "client.h"
#include "logger.h"
#include "resend.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
Client client;
Logger logger;
void handler_SIGINT(int signum)
{
    client_challenge_logout(&client, CONFIG_AUTH_VERSION, &logger);
    client_logout(&client, CONFIG_USERNAME, CONFIG_PASSWORD, CONFIG_MAC, CONFIG_AUTH_VERSION, CONFIG_CONTROL_CHECK_STATUS, CONFIG_ADAPTER_NUM, &logger);
}
int main(int argc, char const *argv[])
{
    srand(time(NULL));
    client_init(&client);
    logger_init(&logger);
    client_connect(&client, CONFIG_CLIENT_IP, CONFIG_CLIENT_PORT, CONFIG_SERVER_IP, CONFIG_SERVER_PORT);
    client_challenge_login(&client, CONFIG_AUTH_VERSION, &logger);
    client_login(&client,
                 CONFIG_USERNAME, CONFIG_PASSWORD, CONFIG_IP, CONFIG_MAC, CONFIG_HOST_NAME, CONFIG_OS_INFO, CONFIG_PRIMARY_DNS, CONFIG_DHCP_SERVER,
                 CONFIG_AUTH_VERSION, CONFIG_CONTROL_CHECK_STATUS, CONFIG_ADAPTER_NUM, CONFIG_IP_DOG, &logger);
    signal(SIGINT, handler_SIGINT);
    pthread_t thread_keep_alive_auth, thread_keep_alive_heart_beat, thread_resend_keep_alive_auth, thread_resend_keep_alive_heart_beat;
    ARG_KeepAliveAuth arg_keep_alive_auth = {
        &client,
        &logger};
    if (pthread_create(&thread_keep_alive_auth, NULL, client_run_keep_alive_auth, &arg_keep_alive_auth) != 0)
    {
        perror("error when creating keep alive auth thread");
        exit(EXIT_FAILURE);
    }
    ARG_KeepAliveHeartBeat arg_keep_alive_heart_beat = {
        &client,
        CONFIG_KEEP_ALIVE_HEART_BEAT_VERSION,
        CONFIG_KEEP_ALIVE_FIRST_HEART_BEAT_VERSION,
        CONFIG_KEEP_ALIVE_EXTRA_HEART_BEAT_VERSION,
        CONFIG_IP,
        &logger};
    if (pthread_create(&thread_keep_alive_heart_beat, NULL, client_run_keep_alive_heart_beat, &arg_keep_alive_heart_beat) != 0)
    {
        perror("error when creating keep alive heart beat thread");
        exit(EXIT_FAILURE);
    }
    ARG_Resend arg_resend = {
        &client,
        &logger};
    if (pthread_create(&thread_resend_keep_alive_auth, NULL, resend_run_keep_alive_auth_check_and_resend, &arg_resend) != 0)
    {
        perror("error when creating resend keep alive auth thread");
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&thread_resend_keep_alive_heart_beat, NULL, resend_run_keep_alive_heart_beat_check_and_resend, &arg_resend) != 0)
    {
        perror("error when creating resend keep alive heart beat thread");
        exit(EXIT_FAILURE);
    }
    pthread_join(thread_keep_alive_auth, NULL);
    pthread_join(thread_keep_alive_heart_beat, NULL);
    pthread_join(thread_resend_keep_alive_auth, NULL);
    pthread_join(thread_resend_keep_alive_heart_beat, NULL);
    return 0;
}
