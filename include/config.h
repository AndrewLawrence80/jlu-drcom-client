#ifndef _CONFIG_H
#define _CONFIG_H

/**
 * set to 1 if you want to see the log in console
 */
#define CONFIG_DEBUG 1

/**
 * user info
 */
#define CONFIG_USERNAME "xiaoming22"
#define CONFIG_PASSWORD "xiaoming123456"
#define CONFIG_IP "192.168.1.100"
#define CONFIG_MAC "\x00\x00\x00\x00\x00\x00"
#define CONFIG_HOST_NAME "xiaoming-linux"
#define CONFIG_OS_INFO "5.10.0-amd64" // obtained by `uname -r` on linux
// the following is not required in JLU
#define CONFIG_PRIMARY_DNS "0.0.0.0"
#define CONFIG_DHCP_SERVER "0.0.0.0"

/**
 * auth server address and port
 */
#define CONFIG_SERVER_IP "10.100.61.3"
#define CONFIG_SERVER_PORT 61440

/**
 * client address and port
 */
#define CONFIG_CLIENT_IP "0.0.0.0" // send through any network interface
#define CONFIG_CLIENT_PORT 61440

/**
 * drcom config
 * no need to change in most cases
 */
#define CONFIG_AUTH_VERSION "\x68\x00"
#define CONFIG_KEEP_ALIVE_HEART_BEAT_VERSION "\xdc\x02"       // obtained in response from server after send keep alive auth packet, [28:29)
#define CONFIG_KEEP_ALIVE_FIRST_HEART_BEAT_VERSION "\x0f\x27" // used for only the first keep alive heart beat
#define CONFIG_KEEP_ALIVE_EXTRA_HEART_BEAT_VERSION "\xdb\x02" // if heart beat counter % 21 ==0, an extra heart beat is needed, see details in function keep_alive_heart_beat() implementation
#define CONFIG_CONTROL_CHECK_STATUS "\x00"
#define CONFIG_ADAPTER_NUM "\x00"
#define CONFIG_IP_DOG "\x01"

/**
 * constant for buffer size and msg length
 */
#define CONFIG_SIZE_BUFFER 512
#define CONFIG_SIZE_SALT 4
#define CONFIG_SIZE_MD5_PASSWORD 16
#define CONFIG_SIZE_KEEP_ALIVE_AUTH 38
#define CONFIG_SIZE_KEEP_ALIVE_HEART_BEAT 40
#define CONFIG_SIZE_SERVER_DRCOM_INDICATOR 16
#define CONFIG_SIZE_HEART_BEAT_SERVER_TOKEN 4
#define CONFIG_SIZE_CHALLENGE 20
#define CONFIG_SIZE_LOGOUT 80

#endif