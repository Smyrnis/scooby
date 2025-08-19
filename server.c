#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

#else
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif



#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define BUFFER_SIZE 8192
#define WEB_ROOT "./www"
#define THREAD_POOL_SIZE 8
#define QUEUE_SIZE 64
#define MAX_HEADERS 32

#define MAX_REQUEST_SIZE 65536
#define MAX_HEADER_SIZE 8192
#define MAX_PATH_LENGTH 2048
#define MAX_METHOD_LENGTH 16
#define MAX_HEADER_NAME_LENGTH 128
#define MAX_HEADER_VALUE_LENGTH 4096

// --------- Functions that need recognition --------------

void send_404(int client_fd, SSL *ssl, struct sockaddr_in client_addr, const char *path);
int ssl_write(SSL *ssl, int fd, const void *buf, int len);

// -------------------------------------------------------
int execute_php(int client_fd, SSL *ssl, const char *method, const char *path, 
                struct sockaddr_in client_addr, const char *body, int body_len) {

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s%s", WEB_ROOT, path);

    struct stat st;
    if (stat(script_path, &st) != 0) {
        send_404(client_fd, ssl, client_addr, path);
        return 404;
    }

#ifdef _WIN32
    // Windows Implementation
    HANDLE hStdInRead, hStdInWrite;
    HANDLE hStdOutRead, hStdOutWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) return 500;
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return 500;

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.hStdInput = hStdInRead;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), "php-cgi.exe -f \"%s\"", script_path);

    // Environment variables
    SetEnvironmentVariable("REQUEST_METHOD", method);
    SetEnvironmentVariable("SCRIPT_FILENAME", script_path);
    SetEnvironmentVariable("SERVER_PROTOCOL", "HTTP/1.1");
    SetEnvironmentVariable("REDIRECT_STATUS", "200");
    char content_length_str[32];
    snprintf(content_length_str, sizeof(content_length_str), "%d", body_len);
    SetEnvironmentVariable("CONTENT_LENGTH", content_length_str);

    if (!CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hStdInRead); CloseHandle(hStdInWrite);
        CloseHandle(hStdOutRead); CloseHandle(hStdOutWrite);
        return 500;
    }

    // Send POST body if any
    if (body && body_len > 0) {
        DWORD written;
        WriteFile(hStdInWrite, body, body_len, &written, NULL);
    }
    CloseHandle(hStdInWrite);
    CloseHandle(hStdInRead);

    // Read all output
    char buffer[65536];
    DWORD total = 0, n;
    char php_output[65536] = {0};
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer), &n, NULL) && n > 0) {
        if (total + n < sizeof(php_output)) {
            memcpy(php_output + total, buffer, n);
            total += n;
        }
    }
    CloseHandle(hStdOutRead);
    CloseHandle(hStdOutWrite);

    // Find body after PHP headers
    char *body_start = strstr(php_output, "\r\n\r\n");
    if (!body_start) body_start = strstr(php_output, "\n\n");
    if (!body_start) body_start = php_output;
    else body_start += (body_start[1] == '\n') ? 2 : 4;

    // Send proper HTTP headers
    char http_header[512];
    snprintf(http_header, sizeof(http_header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %ld\r\n"
        "\r\n", total - (body_start - php_output));

    ssl_write(ssl, client_fd, http_header, strlen(http_header));
    ssl_write(ssl, client_fd, body_start, total - (body_start - php_output));

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

#else
    // Linux / MacOS Implementation
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) return 500;

    pid_t pid = fork();
    if (pid < 0) return 500;

    if (pid == 0) { // child
        dup2(pipe_in[0], STDIN_FILENO);
        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_in[1]);
        close(pipe_out[0]);

        setenv("REQUEST_METHOD", method, 1);
        setenv("SCRIPT_FILENAME", script_path, 1);
        setenv("SERVER_PROTOCOL", "HTTP/1.1", 1);
        setenv("REDIRECT_STATUS", "200", 1);

        char content_length_str[32];
        snprintf(content_length_str, sizeof(content_length_str), "%d", body_len);
        setenv("CONTENT_LENGTH", content_length_str, 1);

        execlp("php-cgi", "php-cgi", NULL);
        perror("execlp");
        exit(1);
    } else { // parent
        close(pipe_in[0]);
        close(pipe_out[1]);

        if (body && body_len > 0) {
            ssize_t written = 0;
            while (written < body_len) {
                ssize_t n = write(pipe_in[1], body + written, body_len - written);
                if (n <= 0) break;
                written += n;
            }
        }
        close(pipe_in[1]);

        // Read all output from PHP-CGI
        char buffer[65536];
        ssize_t total = 0, n;
        char php_output[65536] = {0};
        while ((n = read(pipe_out[0], buffer, sizeof(buffer))) > 0) {
            if (total + n < sizeof(php_output)) {
                memcpy(php_output + total, buffer, n);
                total += n;
            }
        }
        close(pipe_out[0]);

        // Find body start
        char *body_start = strstr(php_output, "\r\n\r\n");
        if (!body_start) body_start = strstr(php_output, "\n\n");
        if (!body_start) body_start = php_output;
        else body_start += (body_start[1] == '\n') ? 2 : 4;

        // Send proper HTTP response over SSL
        char http_header[512];
        snprintf(http_header, sizeof(http_header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %ld\r\n"
            "\r\n", total - (body_start - php_output));

        ssl_write(ssl, client_fd, http_header, strlen(http_header));
        ssl_write(ssl, client_fd, body_start, total - (body_start - php_output));

        waitpid(pid, NULL, 0);
    }
#endif

    return 200;
}


int http_server_fd, https_server_fd;

SSL_CTX *ssl_ctx = NULL;

void log_request(const char *client_ip, const char *method, const char *path, int status_code);
bool validate_http_path(const char *path);

FILE *log_file = NULL;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    char key[128];
    char value[512];
} http_header_t;
typedef struct {
    int client_fd;
    SSL *ssl;
    struct sockaddr_in client_addr;
    bool is_https;
} client_task_t;
void enqueue_task(client_task_t task);

volatile bool running = true;//Server running flag.

client_task_t client_queue[QUEUE_SIZE];
int queue_front = 0, queue_rear = 0, queue_count = 0;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t queue_not_full = PTHREAD_COND_INITIALIZER;



const char *get_mime_type(const char *path) {
    const  char *ext =  strrchr(path, '.');
    if (!ext) return "application/octet-stream";//No extension

    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".htm")  == 0) return "text/html";
    if (strcmp(ext, ".css")  == 0) return "text/css";
    if (strcmp(ext, ".js")   == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png")  == 0) return "image/png";
    if (strcmp(ext, ".jpg")  == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif")  == 0) return "image/gif";
    if (strcmp(ext, ".svg")  == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico")  == 0) return "image/x-icon";
    if (strcmp(ext, ".woff") == 0) return "font/woff";
    if (strcmp(ext, ".woff2")== 0) return "font/woff2";
    if (strcmp(ext, ".ttf")  == 0) return "font/ttf";
    if (strcmp(ext, ".eot")  == 0) return "application/vnd.ms-fontobject";
    if (strcmp(ext, ".mp4")  == 0) return "video/mp4";
    if (strcmp(ext, ".pdf")  == 0) return "application/pdf";

    return "application/octet-stream";//fallback for unkown type.
}

//SSL-aware read/write wrappers
int ssl_read(SSL *ssl, int fd, void *buf, int len) {
    if (ssl) {
        return SSL_read(ssl, buf, len);
    }
    return read(fd, buf, len);
}

int ssl_write(SSL *ssl, int fd, const void *buf, int len) {
    if (ssl) {
        return SSL_write(ssl, buf, len);
    }
    return write(fd, buf, len);
}

void send_404(int client_fd, SSL *ssl, struct sockaddr_in client_addr, const char *path) {
    const char *error_path = WEB_ROOT "/404.html";
    int fd = open(error_path, O_RDONLY);
    if (fd == -1) {
        // fallback plain text
        const char *msg = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        ssl_write(ssl, client_fd, msg, strlen(msg));
        return;
    }

    struct stat st;
    if (stat(error_path, &st) == -1) {
        close(fd);
        const char *msg = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        ssl_write(ssl, client_fd, msg, strlen(msg));
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 404 Not Found\r\n"
             "Content-Length: %ld\r\n"
             "Content-Type: text/html\r\n"
             "Connection: close\r\n\r\n",
             st.st_size);
    ssl_write(ssl, client_fd, header, strlen(header));

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        ssl_write(ssl, client_fd, buffer, bytes_read);
    }
    close(fd);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    log_request(client_ip, "GET", path, 404);
}

void send_403(int client_fd, SSL *ssl) {
    const char *error_path = WEB_ROOT "/403.html";
    int fd = open(error_path, O_RDONLY);
    if (fd == -1) {
        const char *msg = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\n403 Forbidden";
        ssl_write(ssl, client_fd, msg, strlen(msg));
        return;
    }

    struct stat st;
    if (stat(error_path, &st) == -1) {
        close(fd);
        const char *msg = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\n403 Forbidden";
        ssl_write(ssl, client_fd, msg, strlen(msg));
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 403 Forbidden\r\n"
             "Content-Length: %ld\r\n"
             "Content-Type: text/html\r\n"
             "Connection: close\r\n\r\n",
             st.st_size);
    ssl_write(ssl, client_fd, header, strlen(header));

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        ssl_write(ssl, client_fd, buffer, bytes_read);
    }
    close(fd);
}

void url_decode(char *dst, const char *src) {//no usage
    while (*src) {
        if (*src =='%' && isxdigit(src[1]) && isxdigit(src[2])){
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char) strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

void generate_directory_listing(int client_fd, SSL *ssl,const char *fs_path, const char *url_path, bool head_only) {
    DIR *dir = opendir(fs_path);
    if (!dir) {
        send_404(client_fd, ssl, (struct sockaddr_in){0}, url_path);
        return;
    }

    char html[8192];
    int offset = 0;
    if (offset >= sizeof(html) - 512) return;
    offset += snprintf(html + offset, sizeof(html) - offset,
        "<html><head><title>Index of %s</title></head><body><h1>Index of %s</h1><ul>",
        url_path, url_path);

    // Parent directory link
    if (strcmp(url_path, "/") != 0)
        offset += snprintf(html + offset, sizeof(html) - offset, "<li><a href=\"../\">../</a></li>");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0) continue;
        if (offset >= sizeof(html) - 100) break;
        offset += snprintf(html + offset, sizeof(html) - offset,
            "<li><a href=\"%s%s%s\">%s</a></li>",
            url_path,
            url_path[strlen(url_path) - 1] == '/' ? "" : "/",
            entry->d_name,
            entry->d_name);
    }

    offset += snprintf(html + offset, sizeof(html) - offset, "</ul></body></html>");
    closedir(dir);

    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n\r\n"
        "Connection: close\r\n\r\n",
         offset);

        ssl_write(ssl, client_fd, header, strlen(header));
        if (!head_only)
            ssl_write(ssl, client_fd, html, offset);
}

bool is_valid_path(const char *path) {
    if (!validate_http_path(path)) return false;

    //Decode Url encoding properly
    char decoded[PATH_MAX];
    url_decode(decoded, path);
    //check agian after decoding
    if (strstr(decoded, "..") || strstr(decoded, "~")) return false;
   //Check for raw ".."
    if (strstr(path, "..") != NULL)
        return false;

    //Check for encoded "../" -> %2e%2e  or %2e%2e/
    if (strstr(path, "%2e") != NULL || strstr(path, "%2E") != NULL)
        return false;
        
    //Check resolved realpath is still under WEB_ROOT
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path),"%s%s", WEB_ROOT, path);

    char resolved[PATH_MAX];
    if (!realpath(full_path, resolved)){
        return false;//Invalid path or symlink error
    }

    //Ensure resolved path is under WEB_ROOT
    char webroot_resolved[PATH_MAX];
    if (realpath(WEB_ROOT, webroot_resolved) ==NULL)
        {
            perror("realpath failed");
            return 0;
        }
    if (strncmp(resolved,  webroot_resolved, strlen(webroot_resolved)) != 0) {
        return false;
    }
    
    return true;
}
//Ensure request path stays within roo_directory // NO USAGE
bool sanitize_path(const char *path, const char *root, char *safe_out, size_t safe_size){
    char decoded[PATH_MAX];
    url_decode(decoded, path);
    //avoid starting with ".." or starting with "/"
    if (strstr(decoded, "..") != NULL || decoded[0] != '/'){
        return false;
    }

    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path),"%s%s", root, decoded);

    char *real = realpath(full_path, NULL);
    if (!real) return false;
    //Ensure resolved path starts with root directory.
    bool safe = strncmp(real, root, strlen(root)) == 0;
    if (safe) {
        strncpy(safe_out, real, safe_size - 1);
        safe_out[safe_size - 1] = '\0';
    }
    free(real);
    return safe;
}

bool parse_request_line(const char *request_line, char *method, size_t method_size, char *path, size_t path_size) {
    int ret = sscanf(request_line, "%s %s", method, path);
    if (ret != 2) {
        return false;// failed to parse
    }
    return true;
}

bool validate_http_method(const char *method) {
    if (!method || strlen(method) > 16) return false;
    return (strcmp(method, "GET") == 0 ||
            strcmp(method, "POST") == 0 ||
            strcmp(method, "HEAD") == 0); 
}

bool validate_http_path(const char *path) {
    if (!path || strlen(path) > 2048) return false;
    if (path[0] != '/') return false;

    //Check for directory traversal
    if(strstr(path, "../") || strstr(path, "..\\")) return false;
    if(strstr(path, "%2e%2e")) return false;

    return true;
}

bool validate_header_size(const char *buffer, int total_read) {
    if (total_read > MAX_REQUEST_SIZE) return false;

    char *header_end = strstr(buffer, "\r\n\r\n");
    if (header_end && (header_end - buffer) > MAX_HEADER_SIZE) return false;

    return true;
}

bool is_rated_limited(const char *client_ip) {
    return false; // Disable rate limiting for now.
}

int server_file(int client_fd, SSL *ssl, const char *method, const char *path, struct sockaddr_in client_addr, bool head_only) {
    
    if (!is_valid_path(path)) {
        send_403(client_fd, ssl);   
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        log_request(client_ip, "INVALID", path, 403);
        return 403;
    }

    char full_path[1024];
    if (strlen(WEB_ROOT) + strlen(path) >= sizeof(full_path)){
        send_403(client_fd, ssl);
        return 403;
    }
    snprintf(full_path, sizeof(full_path), "%s%s", WEB_ROOT, path);

    // Default to index.html if root is requested
    if (strcmp(path, "/") == 0)
        snprintf(full_path, sizeof(full_path), "%s/index.html", WEB_ROOT);

    int fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        send_404(client_fd, ssl, client_addr, path);
        return 404;
    }

    struct stat st;
    if (stat(full_path, &st) == -1) {
        close(fd);
        send_404(client_fd, ssl, client_addr, path);
        return 404;
    }
    

    if (S_ISDIR(st.st_mode)){
        // Append index.html if it exists.
        char index_path[1035];
        snprintf(index_path,  sizeof(index_path), "%s/index.html", full_path);

        if (access(index_path, F_OK) == 0) {
            //serve index.html
            int index_fd = open(index_path, O_RDONLY);
            if (index_fd == -1) {
                send_404(client_fd, ssl, client_addr, path);
                return 404;
            }

            struct stat index_stat;
            if (stat(index_path, &index_stat) == -1) {
                close(index_fd);
                send_404(client_fd, ssl, client_addr, path);
                return 404;
            }

            char header[1024];
            snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %ld\r\n"
                "Content-Type: text/html\r\n"
                "Cache-Control: public, max-age=86400\r\n"//caches for 1 day.
                "Connection: close\r\n\r\n",
                index_stat.st_size);
            ssl_write(ssl, client_fd, header, strlen(header));

            if (!head_only) {
                char file_buffer[BUFFER_SIZE];
                int bytes_read;
                while ((bytes_read = read(index_fd, file_buffer, BUFFER_SIZE)) > 0)
                    ssl_write(ssl, client_fd, file_buffer, bytes_read);
            }

            close(fd);//Close of the orginal directory fd
            close(index_fd); //Close of the index_fd
            return 200;
        } else {
            // No index.html -> genetate directory listing.
            generate_directory_listing(client_fd, ssl, full_path, path, head_only);
            close(fd);
            return 0;
        }
    }
    // Save regular file
    char header[1024];
    snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: %ld\r\n"
            "Content-Type: %s\r\n"
            "X-Content-Type-Options: nosniff\r\n"          
            "X-Frame-Options: DENY\r\n"                    
            "X-XSS-Protection: 1; mode=block\r\n"          
            "Strict-Transport-Security: max-age=31536000\r\n"
            "Content-Security-Policy: default-src 'self'\r\n" 
            "Cache-Control: public, max-age=86400\r\n"//Caches for 1 day
            "Connection: close\r\n\r\n",
            st.st_size, get_mime_type(full_path));
    ssl_write(ssl, client_fd, header, strlen(header));

    if (!head_only) {
        char file_buffer[BUFFER_SIZE];
        int bytes_read;
        while ((bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0)
            ssl_write(ssl, client_fd, file_buffer, bytes_read);
    }

    close(fd);
    return 200;
}


void handle_sigint(int sig) {
    printf("\nShutting down server gracefully...\n");
    running = false;
    // Close server sockets immediately to stop accepting new connections
    close(http_server_fd);
    close(https_server_fd);
    // wake all waiting threads
    pthread_cond_broadcast(&queue_not_empty);
    pthread_cond_broadcast(&queue_not_empty); // Wake all threads
}

void log_request(const char *client_ip, const char *method, const char *path, int status_code) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    pthread_mutex_lock(&log_mutex);
    fprintf(log_file, "[%s] %s \"%s %s\" %d\n", time_buf, client_ip, method, path, status_code);
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}

void enqueue_task(client_task_t task) {
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == QUEUE_SIZE) {
        pthread_cond_wait(&queue_not_full, &queue_mutex);
    }

    client_queue[queue_rear] = task;
    queue_rear = (queue_rear + 1) % QUEUE_SIZE;
    queue_count ++;

    pthread_cond_signal(&queue_not_empty);
    pthread_mutex_unlock(&queue_mutex);

}

client_task_t dequeue() {
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == 0 && running) {
        pthread_cond_wait(&queue_not_empty, &queue_mutex);
    }
    client_task_t task = { .client_fd = -1}; //default value if shutting down
    if (!running) {
        // When shutting down, return poison pill task.
        pthread_mutex_unlock(&queue_mutex);
        return task;
    }
    task = client_queue[queue_front];
    queue_front = (queue_front + 1) % QUEUE_SIZE;
    queue_count--;

    pthread_cond_signal(&queue_not_full);
    pthread_mutex_unlock(&queue_mutex);
    return task;
}

void *worker_thread(void *arg) {
    char buffer[BUFFER_SIZE];
    http_header_t headers[MAX_HEADERS];
    int header_count = 0;
    int status_code = 500;

    while(running) {
        client_task_t task = dequeue();
        if (task.is_https && ssl_ctx) {
            task.ssl = SSL_new(ssl_ctx);
            if (!task.ssl) {
                close(task.client_fd);
                continue;
            }
            SSL_set_fd(task.ssl, task.client_fd);

            if (SSL_accept(task.ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(task.ssl);
                close(task.client_fd);
                continue;
            }
        }
        if (task.client_fd == -1) break;// Shutdown signal - exit thread.

        int total_read = 0;
        int header_end = -1;

        // Read headers fully first:
        while (total_read < BUFFER_SIZE - 1) {
            int r = ssl_read(task.ssl, task.client_fd, buffer + total_read, BUFFER_SIZE - 1 - total_read);
            if (r <= 0) {
                close(task.client_fd);
                return NULL;
            }
            total_read += r;
            buffer[total_read] = '\0';

            char *pos = strstr(buffer, "\r\n\r\n");
            if (pos) {
                header_end = (pos - buffer) + 4;
                break;
            }
        }

        // Parse request line 
        char method[17], path[2049], version[16];
        char *saveptr;
        char *line = strtok_r(buffer, "\r\n", &saveptr);
        if (sscanf(line, "%16s %2049s %15s", method, path, version) != 3) {
            const char *msg = "HTTP/1.1 400 Bad Request\r\n\r\n";
            ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
            close(task.client_fd);
            continue;
        }

        if (!validate_http_method(method)) {
            const char *msg = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
            close(task.client_fd);
            continue;
        }
        if (!validate_http_path(path)) {
            const char *msg = "HTTP/1.1 400 Bad Request\r\n\r\n";
            ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
            close(task.client_fd);
            continue;
        }
        //Parse headers
        header_count = 0;
        while ((line = strtok_r(NULL, "\r\n", &saveptr)) && header_count < MAX_HEADERS)
        {
            if (strlen(line) > MAX_HEADER_VALUE_LENGTH) {
                //if header to long - reject
                const char *msg = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
                ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
                close(task.client_fd);
                goto cleanup;
            }

            char *sep = strchr(line, ':');
            if (sep && sep != line) {
                size_t key_len = sep - line;
                if (key_len >= sizeof(headers[header_count].key))
                    key_len = sizeof(headers[header_count].key) - 1;

                strncpy(headers[header_count].key, line, key_len);
                headers[header_count].key[key_len] = '\0';
                
                char  *value_start = sep + 1;
                while (*value_start == ' ') value_start++;
                
                strncpy(headers[header_count].value, value_start, sizeof(headers[header_count].value) - 1);
                headers[header_count].value[sizeof(headers[header_count].value) - 1] = '\0';

                header_count++;
            }
        }
        // Convert client IP to readable string
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(task.client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

        char *body = NULL;
        int content_length = 0;
        // POST method..Handle 
        if(strcmp(method, "POST") == 0) {
            //int content_length = 0;
            for (int i = 0; i < header_count; i++) {
                if (strcasecmp(headers[i].key, "Content-Length") == 0) {
                    content_length = atoi(headers[i].value);
                    break;
                }
            }

            if (content_length <= 0 || content_length > 1024 * 1024) {//1MB Limit
                const char *msg = "HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\n\r\n";
                ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
                shutdown(task.client_fd, SHUT_WR);
                close(task.client_fd);
                continue;;
            }

            char *body = malloc(content_length + 1);
            if (!body) {
                //Handle memory failure
                const char *msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
                shutdown(task.client_fd, SHUT_WR);
                close(task.client_fd);
                continue;;
            }
            // Calc how many body bytes we already have in buffer.
            int body_in_buffer = total_read - header_end;
            if (body_in_buffer > content_length)
                body_in_buffer = content_length;

            memcpy(body, buffer + header_end, body_in_buffer);

            int body_received = body_in_buffer;
            while (body_received < content_length) {
                int r = ssl_read(task.ssl, task.client_fd, body + body_received, content_length - body_received);
                if (r <= 0) break;
                body_received += r;
            }
            body[content_length] = '\0';

            // Send the response header and echo body.
            char response_header[256];
            snprintf(response_header, sizeof(response_header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n\r\n",
                content_length);

            if (write(task.client_fd, response_header, strlen(response_header)) < 0 ||
                write(task.client_fd, body, content_length) < 0) {
                perror("write");//Report if something went wrong.
            }
            // LOGGING: move client_ip above this block (see note below)
            printf("Received POST: %.*s\n", content_length, body);
            log_request(client_ip, method, path, 200);

            free(body);
            shutdown(task.client_fd, SHUT_WR);
            close(task.client_fd);
            return 0; // EXIT cleanly
        }
        
        status_code = 200;
        if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0 || strcmp(method, "POST") == 0) {
            if (strstr(path, ".php")) {
                status_code = execute_php(task.client_fd, task.ssl, method, path, task.client_addr, body, content_length);
            } else {
            status_code = server_file(task.client_fd, task.ssl, method, path, task.client_addr, strcmp(method, "HEAD") == 0);
            }
        } else {
            const char *msg = 
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Allow: GET, HEAD, POST\r\n"
                "Content-Length: 0\r\n\r\n";
            ssl_write(task.ssl, task.client_fd, msg, strlen(msg));
            status_code = 405;
        }
        cleanup:
        if (task.ssl) {
            SSL_set_shutdown(task.ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
            SSL_free(task.ssl);
        }
        log_request(client_ip, method, path, status_code);
        close(task.client_fd);
        }

    return NULL;
}

int main() {
    //SSl initialization
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Configure SSl
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ssl_ctx,  "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS");
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    //load certificate and key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Cannot load certificate file 'server.crt'\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Cannot load private key 'server.key'\n");
        exit(EXIT_FAILURE);
    }

    //Verify key matches to certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Privateo key does not match cerificate\n");
        exit(EXIT_FAILURE);
    }

    printf("SSL context initialized successfully\n");

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int opt = 1;

    //create HTTP server socket
    http_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (http_server_fd == -1) {
        perror("http socket");
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(http_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))){
        perror("http setsockopt");
        close(http_server_fd);
        exit(EXIT_FAILURE);
    }
    // create HTTPS server socket
    https_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (https_server_fd == -1){
        perror("https setsockopt");
        close(http_server_fd);
        close(https_server_fd);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint);

    //bind HTTP server port:8080
    struct sockaddr_in http_server_addr;
    http_server_addr.sin_family = AF_INET;
    http_server_addr.sin_port = htons(HTTP_PORT); //8080
    http_server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(http_server_fd, (struct sockaddr*)&http_server_addr, sizeof(http_server_addr)) < 0) {
    perror("http bind");
    close(http_server_fd);
    close(https_server_fd);
    exit(EXIT_FAILURE);
}

if (listen(http_server_fd, 10) < 0) {
    perror("http listen");
    close(http_server_fd);
    close(https_server_fd);
    exit(EXIT_FAILURE);
}

// Bind HTTPS server (port 8443)
struct sockaddr_in https_server_addr;
https_server_addr.sin_family = AF_INET;
https_server_addr.sin_port = htons(HTTPS_PORT);  // 8443
https_server_addr.sin_addr.s_addr = INADDR_ANY;

if (bind(https_server_fd, (struct sockaddr*)&https_server_addr, sizeof(https_server_addr)) < 0) {
    perror("https bind");
    close(http_server_fd);
    close(https_server_fd);
    exit(EXIT_FAILURE);
}

if (listen(https_server_fd, 10) < 0) {
    perror("https listen");
    close(http_server_fd);
    close(https_server_fd);
    exit(EXIT_FAILURE);
}

// Setup logging and thread pool (your existing code continues here)
log_file = fopen("access.log", "a");
if (!log_file) {
    perror("fopen log file");
    exit(EXIT_FAILURE);
}

printf("Static file server running on http://localhost:%d and https://localhost:%d\n", 
       HTTP_PORT, HTTPS_PORT);

// Setup polling
struct pollfd pfds[2];
pfds[0].fd = http_server_fd;
pfds[0].events = POLLIN;
pfds[1].fd = https_server_fd;
pfds[1].events = POLLIN;

    //int opt = 1
    if (setsockopt(http_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsocketopt");
        close(http_server_fd);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint); // Catch Ctrl + C

    log_file = fopen("access.log", "a");
    if (!log_file) {
        perror("fopen log file");
        exit(EXIT_FAILURE);
    }

    pthread_t thread_pool[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&thread_pool[i], NULL, worker_thread, NULL);
    };

    while (running) {
        int ret = poll(pfds, 2, 500);
        if (ret > 0) {
            //Handle HTTP connections
            if (pfds[0].revents & POLLIN) {
                int client_fd = accept(http_server_fd, (struct sockaddr*)&client_addr, &addr_len);
                if (client_fd >= 0) {
                    client_task_t task = {
                        .client_fd = client_fd,
                        .ssl = NULL,
                        .client_addr = client_addr,
                        .is_https = false
                    };
                    enqueue_task(task);
                }
            }

            //Handle HTTPS connections
            if (pfds[1].revents & POLLIN) {
                int client_fd = accept(https_server_fd, (struct sockaddr*)&client_addr, &addr_len);
                if (client_fd >= 0) {
                    client_task_t task = {
                        .client_fd = client_fd,
                        .ssl = NULL,
                        .client_addr = client_addr,
                        .is_https = true
                    };
                    enqueue_task(task);
                }
            }
        }    
    }
    printf("Almost done...\n");
    close(http_server_fd);
       
    // Signal threads to exit by enqueuing poison pills.
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        client_task_t poison_pill = {
            .client_fd = -1,
            .client_addr = {0}
        };
        enqueue_task(poison_pill);
    }

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(thread_pool[i], NULL);
    }
    printf("Server shutdown complete.\n");
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    fclose(log_file);
    close(https_server_fd);
    return 0;
}
// todo: fix some errors. 
//      add the new features.