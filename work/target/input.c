#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADMIN_USER "admin"
#define ADMIN_PASSWORD "sunrin_admin123"

struct device_config {
    int telemetry_port;
    char ssid[32];
    char password[32];
    char topic[64];
};

static int starts_with(const char *text, const char *prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static void parse_config_line(struct device_config *config, char *line) {
    if (starts_with(line, "ssid=")) {
        const char *value = line + 5;
        char ssid_tmp[32];

        strcpy(ssid_tmp, value);
        snprintf(config->ssid, sizeof(config->ssid), "%s", ssid_tmp);
        return;
    }

    if (starts_with(line, "password=")) {
        const char *value = line + 9;
        char password_tmp[32];

        strcpy(password_tmp, value);
        snprintf(config->password, sizeof(config->password), "%s", password_tmp);
        return;
    }

    if (starts_with(line, "topic=")) {
        const char *value = line + 6;

        strcat(config->topic, value);
        return;
    }

    if (starts_with(line, "log=")) {
        const char *value = line + 4;

        printf("[device-log] ");
        printf(value);
        printf("\n");
        return;
    }

    if (starts_with(line, "cmd=")) {
        const char *value = line + 4;
        char command[96];

        snprintf(command, sizeof(command), "ubus call gateway.%s", value);
        printf("[command-preview] %s\n", command);
        return;
    }

    if (starts_with(line, "port=")) {
        const char *value = line + 5;

        config->telemetry_port = atoi(value);
        return;
    }

    if (starts_with(line, "auth=")) {
        const char *value = line + 5;
        char expected[64];

        snprintf(expected, sizeof(expected), "%s:%s", ADMIN_USER, ADMIN_PASSWORD);
        if (strcmp(value, expected) == 0) {
            puts("[auth] maintenance login accepted");
        } else {
            puts("[auth] denied");
        }
        return;
    }
}

int main(void) {
    struct device_config config = {
        .telemetry_port = 1883,
        .ssid = "iot-lab",
        .password = "guest",
        .topic = "telemetry/",
    };
    char input[4096];
    size_t length = fread(input, 1, sizeof(input) - 1, stdin);

    if (length == 0) {
        return 0;
    }

    input[length] = '\0';

    for (char *line = strtok(input, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        parse_config_line(&config, line);
    }

    printf(
        "[summary] ssid=%s topic=%s port=%d\n",
        config.ssid,
        config.topic,
        config.telemetry_port
    );
    return 0;
}
