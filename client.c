#include "client.h"
#include "encryption.h"
#include "debug_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
void client_init(Client *client_this)
{
    client_this->client_sockfd = -1;
    memset(&(client_this->server_sockaddr), 0, sizeof(client_this->server_sockaddr));
    memset(client_this->login_salt, 0, CONFIG_SIZE_SALT);
    memset(client_this->logout_salt, 0, CONFIG_SIZE_SALT);
    memset(client_this->md5_password, 0, CONFIG_SIZE_MD5_PASSWORD);
    memset(client_this->server_drcom_indicator, 0, CONFIG_SIZE_SERVER_DRCOM_INDICATOR);
    client_this->count_heart_beat = 0;
    memset(client_this->heart_beat_server_token, 0, CONFIG_SIZE_HEART_BEAT_SERVER_TOKEN);
}
void client_connect(Client *client_this, const char *client_ip, unsigned int client_port, const char *server_ip, unsigned int server_port)
{
    client_this->client_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_this->client_sockfd < 0)
    {
        perror("error when creating sockset");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in client_sockaddr;
    memset(&client_sockaddr, 0, sizeof(client_sockaddr));
    client_sockaddr.sin_family = AF_INET;
    client_sockaddr.sin_port = htons(client_port);
    if (inet_pton(AF_INET, client_ip, &(client_sockaddr.sin_addr)) < 0)
    {
        perror("error when assigning client address");
        exit(EXIT_FAILURE);
    }
    socklen_t socklen_client_sockaddr = (socklen_t)sizeof(client_sockaddr);
    if (bind(client_this->client_sockfd, (const struct sockaddr *)&client_sockaddr, socklen_client_sockaddr) < 0)
    {
        perror("error when bind client address");
        exit(EXIT_FAILURE);
    }

    memset(&(client_this->server_sockaddr), 0, sizeof(client_this->server_sockaddr));
    client_this->server_sockaddr.sin_family = AF_INET;
    client_this->server_sockaddr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &((client_this->server_sockaddr).sin_addr)) < 0)
    {
        perror("error when assigning server address");
        exit(EXIT_FAILURE);
    }
}
void client_challenge_login(Client *client_this, const char *auth_version, Logger *logger)
{
    unsigned char buffer_send[CONFIG_SIZE_CHALLENGE] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    /*start build challenge packet*/
    // challenge packet begins with 0x01 0x02
    buffer_send[0] = 0x01;
    buffer_send[1] = 0x02;
    // two random numbers
    buffer_send[2] = rand() % 0xff;
    buffer_send[3] = rand() % 0xff;
    // auth version
    // don't use strlen() here, \x00 will lead to only 1 bit copied
    memcpy(buffer_send + 4, auth_version, 2);
    /*end build challenge packet*/
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    logger_log_challenge_send(buffer_send);
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_CHALLENGE, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during login challenge");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during login challenge");
        exit(EXIT_FAILURE);
    }
    logger_log_challenge_receive(buffer_receive, size_receive);
    // received packet begins with 0x02 0x02
    // then same numbers generated before 2 bit
    // then 4 bit salt
    memcpy(client_this->login_salt, buffer_receive + 4, CONFIG_SIZE_SALT);
}

void client_login(Client *client_this, const char *username, const char *password,
                  const char *ip, const char *mac,
                  const char *host_name, const char *os_info,
                  const char *primary_dns, const char *dhcp_server,
                  const char *auth_version, const char *control_check_status,
                  const char *adapter_num, const char *ip_dog, Logger *logger)
{
    unsigned char buffer_send[CONFIG_SIZE_BUFFER] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    const int SIZE_LOGIN = 334 + (strlen(password) - 1) / 4 * 4;

    /*start build login packet*/
    // 0x03 0x01 0x00 strlen(username)+20 4bit
    buffer_send[0] = 0x03;
    buffer_send[1] = 0x01;
    buffer_send[2] = 0x00;
    buffer_send[3] = strlen(username) + 20;

    // build MD5 digest a for password, md5(0x03 0x01 [salt] [password])
    const int SIZE_MD5A_PLAIN = 2 + 4 + strlen(password);
    unsigned char *md5a_plain = (unsigned char *)malloc(SIZE_MD5A_PLAIN * sizeof(unsigned char));
    md5a_plain[0] = 0x03;
    md5a_plain[1] = 0x01;
    memcpy(md5a_plain + 2, client_this->login_salt, 4);
    memcpy(md5a_plain + 6, password, strlen(password));
    unsigned char md5a[16] = {0}; // MD5 digest is 16 bit;
    encryption_gen_md5(md5a_plain, SIZE_MD5A_PLAIN, md5a);
    free(md5a_plain);
    memcpy(buffer_send + 4, md5a, 16);           // [4:20)
    memcpy(client_this->md5_password, md5a, 16); // for keep alive usage

    // username 36 bit
    memcpy(buffer_send + 20, username, strlen(username)); // [20:56)

    // control check status 1 bit
    memcpy(buffer_send + 56, control_check_status, 1); // [56:57)

    // adapter num 1 bit
    memcpy(buffer_send + 57, adapter_num, 1); //[57:58)

    // mac xor md5a 6 bit
    unsigned char mac_xor_md5a[6] = {0};
    encryption_gen_xor((unsigned char *)mac, md5a, 6, mac_xor_md5a, 6);
    memcpy(buffer_send + 58, mac_xor_md5a, 6); // [58:64)

    // build MD5 digest b for password, md5(0x01 [salt] 0x00 0x00 0x00 0x00 [password])
    const int SIZE_MD5B_PLAIN = 9 + strlen(password);
    unsigned char *md5b_plain = (unsigned char *)malloc(SIZE_MD5B_PLAIN * sizeof(unsigned char));
    memset(md5b_plain, 0, SIZE_MD5B_PLAIN);
    md5b_plain[0] = 0x01;
    memcpy(md5b_plain + 1, password, strlen(password));
    memcpy(md5b_plain + 1 + strlen(password), client_this->login_salt, 4);
    unsigned char md5b[16] = {0};
    encryption_gen_md5(md5b_plain, SIZE_MD5B_PLAIN, md5b);
    free(md5b_plain);
    memcpy(buffer_send + 64, md5b, 16); // [64,80)

    // ip indicator
    buffer_send[80] = 0x01;

    // client ip 4 bit
    unsigned char tmp_ip[4] = {0};
    sscanf(ip, "%hhd.%hhd.%hhd.%hhd", &tmp_ip[0], &tmp_ip[1], &tmp_ip[2], &tmp_ip[3]);
    memcpy(buffer_send + 81, tmp_ip, 4); // [81:85)
    
    // concat "\x14\x00\x07\x0b" to first 97 bit, calculate MD5 digest c, md5([first 97 bit] 0x14 0x00 0x07 0x0b)
    unsigned char md5c_plain[101] = {0};
    memcpy(md5c_plain, buffer_send, 97);
    md5c_plain[97] = 0x14;
    md5c_plain[98] = 0x00;
    md5c_plain[99] = 0x07;
    md5c_plain[100] = 0x0b;
    unsigned char md5c[16] = {0};
    encryption_gen_md5(md5c_plain, 101, md5c);
    memcpy(buffer_send + 97, md5c, 8); // [97,105)

    // ip dog 1 bit, delimiter 0x00 4 bit, default set by ``unsigned char buffer_send[CONFIG_SIZE_BUFFER]={0}`` at the beginning
    memcpy(buffer_send + 105, ip_dog, 1); // [105,110)

    // hostname 32 bit
    const int SIZE_HOSTNAME = strlen(host_name) <= 32 ? strlen(host_name) : 32;
    memcpy(buffer_send + 110, host_name, SIZE_HOSTNAME); // [110,142)

    // primary dns 4 bit
    unsigned char tmp_primary_dns[4] = {0};
    sscanf(primary_dns, "%hhd.%hhd.%hhd.%hhd", &tmp_primary_dns[0], &tmp_primary_dns[1], &tmp_primary_dns[2], &tmp_primary_dns[3]);
    memcpy(buffer_send + 142, tmp_primary_dns, 4); // [142,146)

    // dhcp server 4 bit
    unsigned char tmp_dhcp_server[4] = {0};
    sscanf(dhcp_server, "%hhd.%hhd.%hhd.%hhd", &tmp_dhcp_server[0], &tmp_dhcp_server[1], &tmp_dhcp_server[2], &tmp_dhcp_server[3]);
    memcpy(buffer_send + 146, tmp_dhcp_server, 4); // [146,150)

    // all zero util 181 [150:181)

    // 0x01 1 bit, unknown meaning
    buffer_send[181] = 0x01;

    // drcom indicator 8 bit
    const char *DRCOM_INDICATOR = "\x44\x72\x43\x4f\x4d\x00\xcf\x07";
    memcpy(buffer_send + 182, DRCOM_INDICATOR, 8); // [182:190)

    // auth version 2 bit
    memcpy(buffer_send + 190, auth_version, 2); // [190:192)

    // OS info unknown bit, but zero padding after OS info util 246th bit
    const int SIZE_OS_INFO = strlen(os_info) <= 54 ? strlen(os_info) : 54;
    memcpy(buffer_send + 192, os_info, SIZE_OS_INFO); // [192:246)

    // unknown meaning fixed indicator 40 bit, same in gui drcom client across different linux machine
    // zero padding util 310th bit
    const char *UNKNOWN_INDICATOR = "\x66\x34\x37\x64\x62\x62\x35\x39"
                                    "\x63\x33\x34\x35\x39\x30\x31\x62"
                                    "\x34\x33\x31\x31\x39\x32\x62\x62"
                                    "\x31\x66\x62\x66\x63\x66\x64\x33"
                                    "\x33\x66\x34\x33\x34\x32\x31\x31";
    memcpy(buffer_send + 246, UNKNOWN_INDICATOR, 40); // [246:310)

    // auth version 2 bit
    memcpy(buffer_send + 310, auth_version, 2); // [310,312)

    // 0x00 1 bit, nothing to do

    // password length 1 bit
    buffer_send[313] = strlen(password);

    // ror, the length is min(16,strlen(password)), ror(password ^ md5a)
    const int SIZE_ROR_PASSWORD = strlen(password) <= 16 ? strlen(password) : 16;
    unsigned char *password_xor_md5a = (unsigned char *)malloc(SIZE_ROR_PASSWORD * sizeof(unsigned char));
    memset(password_xor_md5a, 0, SIZE_ROR_PASSWORD);
    encryption_gen_xor(md5a, (unsigned char *)password, 16, password_xor_md5a, SIZE_ROR_PASSWORD);
    unsigned char *password_ror = (unsigned char *)malloc(SIZE_ROR_PASSWORD * sizeof(unsigned char));
    memset(password_ror, 0, SIZE_ROR_PASSWORD);
    encryption_gen_ror(password_xor_md5a, SIZE_ROR_PASSWORD, password_ror);
    memcpy(buffer_send + 314, password_ror, SIZE_ROR_PASSWORD);
    free(password_xor_md5a);
    free(password_ror);

    // 0x02 0x0c 2 bit
    buffer_send[314 + SIZE_ROR_PASSWORD] = 0x02;
    buffer_send[315 + SIZE_ROR_PASSWORD] = 0x0c;

    // checksum 4 bit
    const int SIZE_CHECKSUM_PLAIN = 316 + SIZE_ROR_PASSWORD + 6 + 6; // data (316 + SIZE_ROR_PASSWORD bit) + 0x01 0x26 0x07 0x11 0x00 0x00 (6 bit)+ mac (6 bit)
    unsigned char *checksum_plain = (unsigned char *)malloc((SIZE_CHECKSUM_PLAIN) * sizeof(unsigned char));
    memset(checksum_plain, 0, SIZE_CHECKSUM_PLAIN);
    memcpy(checksum_plain, buffer_send, 316 + SIZE_ROR_PASSWORD);
    const char *checksum_salt = "\x01\x26\x07\x11\x00\x00";
    memcpy(checksum_plain + 316 + SIZE_ROR_PASSWORD, checksum_salt, 6);
    memcpy(checksum_plain + 316 + SIZE_ROR_PASSWORD + 6, mac, 6);
    unsigned char checksum[4] = {0};
    encryption_gen_checksum(checksum_plain, SIZE_CHECKSUM_PLAIN, checksum, 4);
    memcpy(buffer_send + 316 + SIZE_ROR_PASSWORD, checksum, 4);
    free(checksum_plain);

    // 0x00 0x00 2 bit, nothing to do

    // mac 6 bit
    memcpy(buffer_send + 322 + SIZE_ROR_PASSWORD, mac, 6);

    // zero padding, default set by ``unsigned char buffer_send[CONFIG_SIZE_BUFFER]={0}`` at the beginning
    int len_zero_padding = (4 - strlen(password) % 4) % 4;

    // two random number 2 bit
    buffer_send[328 + SIZE_ROR_PASSWORD + len_zero_padding] = rand() % 0xff;
    buffer_send[329 + SIZE_ROR_PASSWORD + len_zero_padding] = rand() % 0xff;

    /*end build login packet*/

    logger_log_auth_send(buffer_send, SIZE_LOGIN);
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, SIZE_LOGIN, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during login");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during login");
        exit(EXIT_FAILURE);
    }
    logger_log_auth_receive(buffer_receive, size_receive);

    // save server drcom indicator
    memcpy(client_this->server_drcom_indicator, buffer_receive + 23, 16);
}
void client_keep_alive_auth(Client *client_this, Logger *logger, unsigned char *buffer_send, unsigned char *buffer_receive)
{
    memset(buffer_send, 0, CONFIG_SIZE_KEEP_ALIVE_AUTH);
    memset(buffer_receive, 0, CONFIG_SIZE_BUFFER);
    // 0xff 1 bit
    buffer_send[0] = 0xff;

    // md5_password 16 bit
    memcpy(buffer_send + 1, client_this->md5_password, 16); // [1:17)

    // 0x00 3 bit, nothing to do [17:20)

    // server_drcom_indicator 16 bit
    memcpy(buffer_send + 20, client_this->server_drcom_indicator, 16); // [20:36)

    // time stamp 2 bit, increase by 1 per second, local time is a good candidate
    time_t time_now = time(NULL);
    buffer_send[36] = (unsigned char)time_now % (2 << 7);
    time_now /= (2 << 7);
    buffer_send[37] = (unsigned char)time_now % (2 << 7);

    logger_log_keep_alive_auth_send(logger, buffer_send);
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_KEEP_ALIVE_AUTH, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during keep alive auth");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during keep alive auth");
        exit(EXIT_FAILURE);
    }
    logger_log_keep_alive_auth_receive(logger, buffer_receive, size_receive);
}
void *client_run_keep_alive_auth(void *args)
{
    ARG_KeepAliveAuth *arg_keep_alive_auth = (ARG_KeepAliveAuth *)args;
    unsigned char buffer_send[CONFIG_SIZE_KEEP_ALIVE_AUTH] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    while (1)
    {
        client_keep_alive_auth(arg_keep_alive_auth->client, arg_keep_alive_auth->logger, buffer_send, buffer_receive);
        sleep(20);
    }
}
void client_keep_alive_heart_beat(Client *client_this,
                                  const char *keep_alive_heart_beat_version, const char *keep_alive_first_heart_beat_version, const char *keep_alive_extra_heart_beat_version,
                                  const char *ip, Logger *logger, unsigned char *buffer_send, unsigned char *buffer_receive)
{
    // first heart beat
    if (client_this->count_heart_beat == 0)
    {
        memset(buffer_send, 0, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
        memset(buffer_receive, 0, CONFIG_SIZE_BUFFER);
        // 0x07 1 bit
        buffer_send[0] = 0x07;

        // heart_beat_count 1 bit
        buffer_send[1] = (unsigned char)((client_this->count_heart_beat) & 0xff);

        // 0x28 0x00 0x0b 3 bit
        buffer_send[2] = 0x28;
        buffer_send[3] = 0x00;
        buffer_send[4] = 0x0b;

        // 0x01 1 bit
        buffer_send[5] = 0x01;
        // keep alive first heart beat version 2 bit
        memcpy(buffer_send + 6, keep_alive_first_heart_beat_version, 2); // [6:8)

        // random number 4 bit
        buffer_send[8] = rand() % 0xff;
        buffer_send[9] = rand() % 0xff;
        buffer_send[10] = rand() % 0xff;
        buffer_send[11] = rand() % 0xff;

        logger_log_keep_alive_heart_beat_send(logger, buffer_send);
        socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
        ssize_t size_send = -1, size_receive = -1;
        size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
        if (size_send < 0)
        {
            perror("error when sending to server during first heart beat");
            exit(EXIT_FAILURE);
        }
        size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
        if (size_receive < 0)
        {
            perror("error when receiving from server during first heart beat");
            exit(EXIT_FAILURE);
        }
        logger_log_keep_alive_heart_beat_receive(logger, buffer_receive, size_receive);

        ++(client_this->count_heart_beat);
        sleep(1);
    }
    // extra heart beat
    if (client_this->count_heart_beat % 21 == 0)
    {
        memset(buffer_send, 0, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
        memset(buffer_receive, 0, CONFIG_SIZE_BUFFER);
        // 0x07 1 bit
        buffer_send[0] = 0x07;

        // heart_beat_count 1 bit
        buffer_send[1] = (unsigned char)((client_this->count_heart_beat) & 0xff);

        // 0x28 0x00 0x0b 3 bit
        buffer_send[2] = 0x28;
        buffer_send[3] = 0x00;
        buffer_send[4] = 0x0b;

        buffer_send[5] = 0x01;

        // keep alive extra heart beat version 2 bit
        memcpy(buffer_send + 6, keep_alive_extra_heart_beat_version, 2); // [6:8)

        // random number 4 bit
        buffer_send[8] = rand() % 0xff;
        buffer_send[9] = rand() % 0xff;
        buffer_send[10] = rand() % 0xff;
        buffer_send[11] = rand() % 0xff;

        // 0x00 4bit, nothing to do [12:16)

        // heart_beat_server_token 4 bit
        memcpy(buffer_send + 16, client_this->heart_beat_server_token, 4); // [16:20)

        logger_log_keep_alive_heart_beat_send(logger, buffer_send);
        socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
        ssize_t size_send = -1, size_receive = -1;
        size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
        if (size_send < 0)
        {
            perror("error when sending to server during extra heart beat");
            exit(EXIT_FAILURE);
        }
        size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
        if (size_receive < 0)
        {
            perror("error when receiving from server during extra heart beat");
            exit(EXIT_FAILURE);
        }
        logger_log_keep_alive_heart_beat_receive(logger, buffer_receive, size_receive);

        ++(client_this->count_heart_beat);
        sleep(1);
    }

    /*begin 2 turns of heart beat*/
    // 1st turn
    memset(buffer_send, 0, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
    memset(buffer_receive, 0, CONFIG_SIZE_BUFFER);
    // 0x07 1 bit
    buffer_send[0] = 0x07;

    // heart_beat_count 1 bit
    buffer_send[1] = (unsigned char)((client_this->count_heart_beat) & 0xff);

    // 0x28 0x00 0x0b 3 bit
    buffer_send[2] = 0x28;
    buffer_send[3] = 0x00;
    buffer_send[4] = 0x0b;

    buffer_send[5] = 0x01;

    memcpy(buffer_send + 6, keep_alive_heart_beat_version, 2); // [6:8)

    // random number 4 bit
    unsigned char random_token[4] = {0};
    random_token[8] = rand() % 0xff;
    random_token[9] = rand() % 0xff;
    random_token[10] = rand() % 0xff;
    random_token[11] = rand() % 0xff;
    memcpy(buffer_send + 8, random_token, 4); // [8:12)

    // 0x00 4 bit, nothing to do

    // heart_bit_server_token 4 bit, 1st heart beat is 0x00 0x00 0x00 0x00
    memcpy(buffer_send + 16, client_this->heart_beat_server_token, 4);

    logger_log_keep_alive_heart_beat_send(logger, buffer_send);
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during 1st heart beat");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during 1st heart beat");
        exit(EXIT_FAILURE);
    }
    logger_log_keep_alive_heart_beat_receive(logger, buffer_receive, size_receive);
    memcpy(client_this->heart_beat_server_token, buffer_receive + 16, 4);

    ++(client_this->count_heart_beat);

    // 2nd turn
    memset(buffer_send, 0, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT);
    memset(buffer_receive, 0, CONFIG_SIZE_BUFFER);
    // 0x07 1 bit
    buffer_send[0] = 0x07;

    // heart_beat_count 1 bit
    buffer_send[1] = (unsigned char)((client_this->count_heart_beat) & 0xff);

    // 0x28 0x00 0x0b 3 bit
    buffer_send[2] = 0x28;
    buffer_send[3] = 0x00;
    buffer_send[4] = 0x0b;

    buffer_send[5] = 0x03;

    memcpy(buffer_send + 6, keep_alive_heart_beat_version, 2); // [6:8)

    // random number 4 bit
    memcpy(buffer_send + 8, random_token, 4); // [8:12)

    // 0x00 4 bit, nothing to do

    // heart_beat_server_token 4 bit
    memcpy(buffer_send + 16, client_this->heart_beat_server_token, 4); // [16:20)

    // 0x00 4 bit, nothing to do

    // crc 4 bit
    unsigned char crc_plain[28] = {0};
    memcpy(crc_plain, buffer_send, 24);
    unsigned char tmp_ip[4] = {0};
    sscanf(ip, "%hhd.%hhd.%hhd.%hhd", &tmp_ip[0], &tmp_ip[1], &tmp_ip[2], &tmp_ip[3]);
    memcpy(crc_plain + 24, tmp_ip, 4);
    unsigned char crc[4] = {0};
    encryption_gen_crc(crc_plain, 28, crc, 4);
    memcpy(buffer_send + 24, crc, 4);
    // client ip 4 bit
    memcpy(buffer_send + 28, tmp_ip, 4); // [28:32)

    logger_log_keep_alive_heart_beat_send(logger, buffer_send);
    size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during 2nd heart beat");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during 2nd heart beat");
        exit(EXIT_FAILURE);
    }
    logger_log_keep_alive_heart_beat_receive(logger, buffer_receive, size_receive);

    ++(client_this->count_heart_beat);
    /*end 2 turns of heart beat*/
}
void *client_run_keep_alive_heart_beat(void *args)
{
    ARG_KeepAliveHeartBeat *arg_keep_alive_heart_heat = (ARG_KeepAliveHeartBeat *)args;
    unsigned char buffer_send[CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    while (1)
    {
        client_keep_alive_heart_beat(arg_keep_alive_heart_heat->client,
                                     arg_keep_alive_heart_heat->keep_alive_heart_beat_version,
                                     arg_keep_alive_heart_heat->keep_alive_first_heart_beat_version,
                                     arg_keep_alive_heart_heat->keep_alive_extra_heart_beat_version,
                                     arg_keep_alive_heart_heat->ip,
                                     arg_keep_alive_heart_heat->logger,
                                     buffer_send, buffer_receive);
        sleep(20);
    }
}
void client_challenge_logout(Client *client_this, const char *auth_version, Logger *logger)
{
    unsigned char buffer_send[CONFIG_SIZE_CHALLENGE] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    /*start build challenge packet*/
    // challenge packet begins with 0x01 0x03, which is the only difference from challenge_login()
    buffer_send[0] = 0x01;
    buffer_send[1] = 0x03;
    // two random numbers
    buffer_send[2] = rand() % 0xff;
    buffer_send[3] = rand() % 0xff;
    // auth version
    // don't use strlen() here, \x00 will lead to only 1 bit copied
    memcpy(buffer_send + 4, auth_version, 2);
    /*end build challenge packet*/

    logger_log_challenge_send(buffer_send);
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_CHALLENGE, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during logout challenge");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during logout challenge");
        exit(EXIT_FAILURE);
    }
    logger_log_challenge_receive(buffer_receive, size_receive);

    // received packet begins with 0x02 0x03
    // then same numbers generated before 2 bit
    // then 4 bit salt
    memcpy(client_this->logout_salt, buffer_receive + 4, 4);
}
void client_logout(Client *client_this, const char *username, const char *password, const char *mac, const char *auth_version, const char *control_check_status, const char *adapter_num, Logger *logger)
{
    unsigned char buffer_send[CONFIG_SIZE_LOGOUT] = {0};
    unsigned char buffer_receive[CONFIG_SIZE_BUFFER] = {0};
    buffer_send[0] = 0x06;
    buffer_send[1] = 0x01;
    buffer_send[2] = 0x00;
    buffer_send[3] = strlen(username) + 20;
    const int SIZE_MD5A_PLAIN = 2 + 4 + strlen(password);
    unsigned char *md5a_plain = (unsigned char *)malloc(SIZE_MD5A_PLAIN * sizeof(unsigned char));
    memset(md5a_plain, 0, SIZE_MD5A_PLAIN);
    md5a_plain[0] = 0x06;
    md5a_plain[1] = 0x01;
    memcpy(md5a_plain + 2, client_this->logout_salt, 4);
    memcpy(md5a_plain + 6, password, strlen(password));
    unsigned char md5a[16] = {0};
    encryption_gen_md5(md5a_plain, SIZE_MD5A_PLAIN, md5a);
    free(md5a_plain);
    memcpy(buffer_send + 4, md5a, 16); // [4:20)

    // username 36 bit
    memcpy(buffer_send + 20, username, strlen(username)); // [20:56)

    // control check status 1 bit
    memcpy(buffer_send + 56, control_check_status, 1);

    // adapter num 1 bit
    memcpy(buffer_send + 57, adapter_num, 1);

    // mac xor md5a 6 bit
    unsigned char mac_xor_md5a[6] = {0};
    encryption_gen_xor((unsigned char *)mac, md5a, 6, mac_xor_md5a, 6);
    memcpy(buffer_send + 58, mac_xor_md5a, 6); // [58:64)

    // server_drcom_indicator 16 bit
    memcpy(buffer_send + 64, client_this->server_drcom_indicator, 16); // [64:80)

    logger_log_logout_send(buffer_send);
    socklen_t socklen_server_sockaddr = (socklen_t)sizeof(client_this->server_sockaddr);
    ssize_t size_send = -1, size_receive = -1;
    size_send = sendto(client_this->client_sockfd, buffer_send, CONFIG_SIZE_LOGOUT, 0, (const struct sockaddr *)&(client_this->server_sockaddr), socklen_server_sockaddr);
    if (size_send < 0)
    {
        perror("error when sending to server during logout");
        exit(EXIT_FAILURE);
    }
    size_receive = recvfrom(client_this->client_sockfd, buffer_receive, CONFIG_SIZE_BUFFER, 0, (struct sockaddr *)&(client_this->server_sockaddr), &socklen_server_sockaddr);
    if (size_receive < 0)
    {
        perror("error when receiving from server during logout");
        exit(EXIT_FAILURE);
    }
    logger_log_logout_receive(buffer_receive, size_receive);

    close(client_this->client_sockfd);
    exit(EXIT_SUCCESS);
}