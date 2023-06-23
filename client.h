#ifndef _CLIENT_H
#define _CLIENT_H
#include "config.h"
#include "logger.h"
#include <netinet/in.h>
typedef struct
{
    int client_sockfd;
    struct sockaddr_in server_sockaddr;
    // login salt from server after challenge
    unsigned char login_salt[CONFIG_SIZE_SALT];
    // logout salt from server after challenge
    unsigned char logout_salt[CONFIG_SIZE_SALT];
    // md5(0x03 0x01 [salt] [password]) 16 bit, calculated when login, used for login and keep alive auth
    unsigned char md5_password[CONFIG_SIZE_MD5_PASSWORD];
    // server_drcom_indicator: received from server after login
    unsigned char server_drcom_indicator[CONFIG_SIZE_SERVER_DRCOM_INDICATOR];
    // number of sent heart beat
    unsigned long count_heart_beat;

    // get from server during keep alive heart beat
    unsigned char heart_beat_server_token[CONFIG_SIZE_HEART_BEAT_SERVER_TOKEN];
} Client;

typedef struct
{
    Client *client;
    Logger *logger;
} ARG_KeepAliveAuth;

typedef struct
{
    Client *client;
    const char *keep_alive_heart_beat_version;
    const char *keep_alive_first_heart_beat_version;
    const char *keep_alive_extra_heart_beat_version;
    const char *ip;
    Logger *logger;
} ARG_KeepAliveHeartBeat;

void client_init(Client *client_this);
void client_connect(Client *client_this, const char *client_ip, unsigned int client_port, const char *server_ip, unsigned int server_port);
void client_challenge_login(Client *client_this, const char *auth_version, Logger *logger);
void client_login(Client *client_this, const char *username, const char *password,
                  const char *ip, const char *mac,
                  const char *host_name, const char *os_info,
                  const char *primary_dns, const char *dhcp_server,
                  const char *auth_version, const char *control_check_status,
                  const char *adapter_num, const char *ip_dog, Logger *logger);
void client_keep_alive_auth(Client *client_this, Logger *logger, unsigned char *buffer_send, unsigned char *buffer_receive);
// used for pthread_create
void *client_run_keep_alive_auth(void *args);
void client_keep_alive_heart_beat(Client *client_this,
                                  const char *keep_alive_heart_beat_version, const char *keep_alive_first_heart_beat_version, const char *keep_alive_extra_heart_beat_version,
                                  const char *ip, Logger *logger, unsigned char *buffer_send, unsigned char *buffer_receive);
void *client_run_keep_alive_heart_beat(void *args);
void client_challenge_logout(Client *client_this, const char *auth_version, Logger *logger);
void client_logout(Client *client_this, const char *username, const char *password, const char *mac, const char *auth_version, const char *control_check_status, const char *adapter_num, Logger *logger);
#endif