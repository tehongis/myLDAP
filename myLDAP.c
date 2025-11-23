// Simple TCP auth server using MySQL for credentials.
// Listens on port 1389 and expects a single-line credential
// in the form: username:password\n
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <mysql.h>
#include <pthread.h>
#include <crypt.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

#define BUF_SIZE 2048
#define DEFAULT_CONFIG_FILE "myLDAP.conf"
#define DEFAULT_SERVER_PORT 1389
#define DEFAULT_BIND_IP "0.0.0.0"
#define DEFAULT_LOG_FILE "server.log"

struct config {
    int server_port;
    char server_bind_ip[256];
    char log_file[256];
    char db_host[256];
    int db_port;
    char db_name[256];
    char db_user[256];
    char db_pass[256];
};

static volatile int keep_running = 1;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char log_file_path[256] = DEFAULT_LOG_FILE;

static void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&log_mutex);
    FILE *f = fopen(log_file_path, "a");
    if (f) {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        char timestr[64];
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
        fprintf(f, "[%s] ", timestr);
        vfprintf(f, fmt, ap);
        fprintf(f, "\n");
        fclose(f);
    }
    pthread_mutex_unlock(&log_mutex);
    va_end(ap);
}

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

// Trim whitespace from start and end of string
static char *trim(char *str) {
    if (!str) return str;
    while (*str && isspace((unsigned char)*str)) str++;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) *end-- = '\0';
    return str;
}

// Load configuration from file
static int load_config(const char *filepath, struct config *cfg) {
    if (!cfg) return -1;
    // Set defaults
    cfg->server_port = DEFAULT_SERVER_PORT;
    snprintf(cfg->server_bind_ip, sizeof(cfg->server_bind_ip), "%s", DEFAULT_BIND_IP);
    snprintf(cfg->log_file, sizeof(cfg->log_file), "%s", DEFAULT_LOG_FILE);
    snprintf(cfg->db_host, sizeof(cfg->db_host), "localhost");
    cfg->db_port = 3306;
    snprintf(cfg->db_name, sizeof(cfg->db_name), "ldap_users");
    snprintf(cfg->db_user, sizeof(cfg->db_user), "ldap");
    snprintf(cfg->db_pass, sizeof(cfg->db_pass), "ldap");

    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "Warning: config file '%s' not found, using defaults\n", filepath);
        return 0; // Not fatal, use defaults
    }

    char line[512];
    int line_num = 0;
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';
        // Skip comments and empty lines
        char *trimmed = trim(line);
        if (!trimmed || *trimmed == '#' || *trimmed == '\0') continue;

        char *sep = strchr(trimmed, '=');
        if (!sep) {
            fprintf(stderr, "Warning: config line %d has no '=', skipping\n", line_num);
            continue;
        }
        *sep = '\0';
        char *key = trim(trimmed);
        char *val = trim(sep + 1);

        if (strcmp(key, "server_port") == 0) {
            cfg->server_port = atoi(val);
        } else if (strcmp(key, "server_bind_ip") == 0) {
            snprintf(cfg->server_bind_ip, sizeof(cfg->server_bind_ip), "%s", val);
        } else if (strcmp(key, "log_file") == 0) {
            snprintf(cfg->log_file, sizeof(cfg->log_file), "%s", val);
        } else if (strcmp(key, "db_host") == 0) {
            snprintf(cfg->db_host, sizeof(cfg->db_host), "%s", val);
        } else if (strcmp(key, "db_port") == 0) {
            cfg->db_port = atoi(val);
        } else if (strcmp(key, "db_name") == 0) {
            snprintf(cfg->db_name, sizeof(cfg->db_name), "%s", val);
        } else if (strcmp(key, "db_user") == 0) {
            snprintf(cfg->db_user, sizeof(cfg->db_user), "%s", val);
        } else if (strcmp(key, "db_pass") == 0) {
            snprintf(cfg->db_pass, sizeof(cfg->db_pass), "%s", val);
        }
    }
    fclose(f);
    return 0;
}

// Verify credentials using stored hashed password (crypt-compatible)
// Returns 1 if auth success, 0 if fail, -1 on error
int mysql_check_credentials(MYSQL *db, const char *user, const char *pass) {
    if (!db || !user || !pass) return -1;
    MYSQL_STMT *stmt = mysql_stmt_init(db);
    if (!stmt) return -1;

    const char *sql = "SELECT password FROM users WHERE username = ? LIMIT 1";
    if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    MYSQL_BIND param;
    memset(&param, 0, sizeof(param));
    unsigned long user_len = strlen(user);
    param.buffer_type = MYSQL_TYPE_STRING;
    param.buffer = (char *)user;
    param.buffer_length = user_len;
    param.length = &user_len;

    if (mysql_stmt_bind_param(stmt, &param) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        return -1;
    }

    MYSQL_RES *meta = mysql_stmt_result_metadata(stmt);
    if (!meta) {
        mysql_stmt_close(stmt);
        return -1;
    }

    MYSQL_BIND result;
    memset(&result, 0, sizeof(result));
    char stored_hash[512];
    unsigned long stored_len = 0;
    result.buffer_type = MYSQL_TYPE_STRING;
    result.buffer = stored_hash;
    result.buffer_length = sizeof(stored_hash) - 1;
    result.is_null = NULL;
    result.length = &stored_len;

    if (mysql_stmt_bind_result(stmt, &result) != 0) {
        mysql_free_result(meta);
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt) != 0) {
        mysql_free_result(meta);
        mysql_stmt_close(stmt);
        return -1;
    }

    int fetch_rc = mysql_stmt_fetch(stmt);
    if (fetch_rc == MYSQL_NO_DATA) {
        mysql_free_result(meta);
        mysql_stmt_close(stmt);
        return 0; // user not found
    }

    if (fetch_rc != 0 && fetch_rc != MYSQL_DATA_TRUNCATED) {
        mysql_free_result(meta);
        mysql_stmt_close(stmt);
        return -1;
    }

    if (stored_len == 0) {
        mysql_free_result(meta);
        mysql_stmt_close(stmt);
        return 0;
    }

    if (stored_len >= result.buffer_length) stored_len = result.buffer_length - 1;
    stored_hash[stored_len] = '\0';

    char *calc = crypt(pass, stored_hash);
    int ok = 0;
    if (calc && strcmp(calc, stored_hash) == 0) ok = 1;

    mysql_free_result(meta);
    mysql_stmt_close(stmt);
    return ok;
}

struct thread_arg {
    int client;
    struct sockaddr_in addr;
    const char *db_host;
    const char *db_user;
    const char *db_pass;
    const char *db_name;
};

static void *client_worker(void *varg) {
    struct thread_arg *arg = varg;
    int client = arg->client;
    char addrstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arg->addr.sin_addr, addrstr, sizeof(addrstr));

    // Create a per-thread MySQL connection
    MYSQL *db = mysql_init(NULL);
    if (!db) {
        log_msg("mysql_init failed for client %s", addrstr);
        close(client);
        free(arg);
        return NULL;
    }
    if (!mysql_real_connect(db, arg->db_host, arg->db_user, arg->db_pass, arg->db_name, 3306, NULL, 0)) {
        log_msg("mysql_real_connect failed for client %s: %s", addrstr, mysql_error(db));
        mysql_close(db);
        close(client);
        free(arg);
        return NULL;
    }

    char buf[BUF_SIZE];
    ssize_t n = recv(client, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        log_msg("recv failed/empty from %s", addrstr);
        close(client);
        mysql_close(db);
        free(arg);
        return NULL;
    }
    buf[n] = '\0';

    char *sep = strchr(buf, ':');
    if (!sep) {
        const char *msg = "ERR_INVALID_FORMAT\n";
        send(client, msg, strlen(msg), 0);
        log_msg("invalid format from %s", addrstr);
        close(client);
        mysql_close(db);
        free(arg);
        return NULL;
    }
    *sep = '\0';
    char *username = buf;
    char *password = sep + 1;
    char *nl = strchr(password, '\n'); if (nl) *nl = '\0';

    int auth = mysql_check_credentials(db, username, password);
    if (auth == 1) {
        const char *ok = "OK\n";
        send(client, ok, strlen(ok), 0);
        log_msg("auth success for user='%s' from %s", username, addrstr);
    } else if (auth == 0) {
        const char *den = "DENIED\n";
        send(client, den, strlen(den), 0);
        log_msg("auth failed for user='%s' from %s", username, addrstr);
    } else {
        const char *err = "ERR_INTERNAL\n";
        send(client, err, strlen(err), 0);
        log_msg("internal error for user='%s' from %s", username, addrstr);
    }

    close(client);
    mysql_close(db);
    free(arg);
    return NULL;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    signal(SIGINT, handle_sigint);

    struct config cfg;
    if (load_config(DEFAULT_CONFIG_FILE, &cfg) != 0) {
        fprintf(stderr, "Error loading configuration\n");
        return 1;
    }

    // Update global log file path
    snprintf(log_file_path, sizeof(log_file_path), "%s", cfg.log_file);

    log_msg("Starting auth server with config from %s", DEFAULT_CONFIG_FILE);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "socket failed: %s\n", strerror(errno));
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // Convert server_bind_ip string to address
    if (inet_pton(AF_INET, cfg.server_bind_ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "invalid bind IP: %s\n", cfg.server_bind_ip);
        close(server_fd);
        return 1;
    }
    addr.sin_port = htons(cfg.server_port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        fprintf(stderr, "listen failed: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    printf("Auth server listening on port %d\n", cfg.server_port);

    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client < 0) {
            if (errno == EINTR) break;
            fprintf(stderr, "accept failed: %s\n", strerror(errno));
            break;
        }

        pthread_t tid;
        struct thread_arg *targ = malloc(sizeof(*targ));
        if (!targ) {
            log_msg("malloc failed for thread_arg");
            close(client);
            continue;
        }
        targ->client = client;
        targ->addr = client_addr;
        targ->db_host = cfg.db_host;
        targ->db_user = cfg.db_user;
        targ->db_pass = cfg.db_pass;
        targ->db_name = cfg.db_name;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_worker, targ) != 0) {
            log_msg("pthread_create failed: %s", strerror(errno));
            close(client);
            free(targ);
        }
        pthread_attr_destroy(&attr);
    }

    close(server_fd);
    printf("Server shutting down\n");
    return 0;
}

