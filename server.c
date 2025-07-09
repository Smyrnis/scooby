#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <poll.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <linux/limits.h>

#define PORT 8080
#define BUFFER_SIZE 8192
#define WEB_ROOT "./www"
#define THREAD_POOL_SIZE 8
#define QUEUE_SIZE 64
#define MAX_HEADERS 32


void log_request(const char *client_ip, const char *method, const char *path, int status_code);


FILE *log_file = NULL;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    char key[128];
    char value[512];
} http_header_t;
typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} client_task_t;

int server_fd;
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

void send_404(int client_fd, struct sockaddr_in client_addr, const char *path) {
    const char *error_path = WEB_ROOT "/404.html";
    int fd = open(error_path, O_RDONLY);
    if (fd == -1) {
        // fallback plain text
        const char *msg = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        write(client_fd, msg, strlen(msg));
        return;
    }

    struct stat st;
    if (stat(error_path, &st) == -1) {
        close(fd);
        const char *msg = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        write(client_fd, msg, strlen(msg));
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 404 Not Found\r\n"
             "Content-Length: %ld\r\n"
             "Content-Type: text/html\r\n"
             "Connection: close\r\n\r\n",
             st.st_size);
    write(client_fd, header, strlen(header));

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        write(client_fd, buffer, bytes_read);
    }
    close(fd);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    log_request(client_ip, "GET", path, 404);
}

void send_403(int client_fd) {
    const char *error_path = WEB_ROOT "/403.html";
    int fd = open(error_path, O_RDONLY);
    if (fd == -1) {
        const char *msg = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\n403 Forbidden";
        write(client_fd, msg, strlen(msg));
        return;
    }

    struct stat st;
    if (stat(error_path, &st) == -1) {
        close(fd);
        const char *msg = "HTTP/1.1 403 Forbidden\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\n403 Forbidden";
        write(client_fd, msg, strlen(msg));
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 403 Forbidden\r\n"
             "Content-Length: %ld\r\n"
             "Content-Type: text/html\r\n"
             "Connection: close\r\n\r\n",
             st.st_size);
    write(client_fd, header, strlen(header));

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        write(client_fd, buffer, bytes_read);
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

void generate_directory_listing(int client_fd, const char *fs_path, const char *url_path, bool head_only) {
    DIR *dir = opendir(fs_path);
    if (!dir) {
        send_404(client_fd, (struct sockaddr_in){0}, url_path);
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

        write(client_fd, header, strlen(header));
        if (!head_only)
            write(client_fd, html, offset);
}

bool is_valid_path(const char *path) {
   //Check for raw ".."
    if (strstr(path, "..") != NULL)
        return false;

    //Check for encoded "../" -> %2e%2e  or %2e%2e/
    if (strcasestr(path, "%2e") != NULL)
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
    realpath(WEB_ROOT, webroot_resolved);
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

int server_file(int client_fd, const char *method, const char *path, struct sockaddr_in client_addr, bool head_only) {
    
    if (!is_valid_path(path)) {
        send_403(client_fd);   
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        log_request(client_ip, "INVALID", path, 403);
        return 403;
    }

    char full_path[1024];
    if (strlen(WEB_ROOT) + strlen(path) >= sizeof(full_path)){
        send_403(client_fd);
        return 403;
    }
    snprintf(full_path, sizeof(full_path), "%s%s", WEB_ROOT, path);

    // Default to index.html if root is requested
    if (strcmp(path, "/") == 0)
        snprintf(full_path, sizeof(full_path), "%s/index.html", WEB_ROOT);

    int fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        send_404(client_fd, client_addr, path);
        return 404;
    }

    struct stat st;
    if (stat(full_path, &st) == -1) {
        close(fd);
        send_404(client_fd, client_addr, path);
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
                send_404(client_fd, client_addr, path);
                return 404;
            }

            struct stat index_stat;
            if (stat(index_path, &index_stat) == -1) {
                close(index_fd);
                send_404(client_fd, client_addr, path);
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
            write(client_fd, header, strlen(header));

            if (!head_only) {
                char file_buffer[BUFFER_SIZE];
                int bytes_read;
                while ((bytes_read = read(index_fd, file_buffer, BUFFER_SIZE)) > 0)
                    write(client_fd, file_buffer, bytes_read);
            }

            close(fd);//Close of the orginal directory fd
            close(index_fd); //Close of the index_fd
            return -1;
        } else {
            // No index.html -> genetate directory listing.
            generate_directory_listing(client_fd, full_path, path, head_only);
            close(fd);
            return 0;
        }
    }
    // Save regular file
    char header[1024];
    snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK \r\n"
            "Content-Length: %ld\r\n"
            "Content-Type: %s\r\n"
            "Cache-Control: public, max-age=86400\r\n"//Caches for 1 day
            "Connection: close\r\n\r\n",
            st.st_size, get_mime_type(full_path));
    write(client_fd, header, strlen(header));

    if (!head_only) {
        char file_buffer[BUFFER_SIZE];
        int bytes_read;
        while ((bytes_read = read(fd, file_buffer, BUFFER_SIZE)) > 0)
            write(client_fd, file_buffer, bytes_read);
    }

    close(fd);
    return 200;
}


void handle_sigint(int sig) {
    printf("\nShutting down server gracefully...\n");
    running = false;
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

void enqueue(int client_fd, struct sockaddr_in client_addr) {
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == QUEUE_SIZE) {
        pthread_cond_wait(&queue_not_full, &queue_mutex);
    }

    client_queue[queue_rear].client_fd = client_fd;
    client_queue[queue_rear].client_addr = client_addr;
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

    while(running) {
        client_task_t task = dequeue();
        if (task.client_fd == -1) break;// Shutdown signal - exit thread.

        int total_read = 0;
        int header_end = -1;

        // Read headers fully first:
        while (total_read < BUFFER_SIZE - 1) {
            int r = read(task.client_fd, buffer + total_read, BUFFER_SIZE - 1 - total_read);
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
        char method[8], path[1024], version[16];
        char *saveptr;
        char *line = strtok_r(buffer, "\r\n", &saveptr);
        if (!line || sscanf(line, "%7s %1023s %15s", method, path, version) != 3) {
            const char *msg = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            write(task.client_fd, msg, strlen(msg));
            close(task.client_fd);
            continue;
        }
        //Parse headers
        header_count = 0;
        while ((line = strtok_r(NULL, "\r\n", &saveptr)) && header_count < MAX_HEADERS)
        {
            if (line[0] == '\0') break;// End of headers.

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

        // POST method..Handle 
        if(strcmp(method, "POST") == 0) {
            int content_length = 0;
            for (int i = 0; i < header_count; i++) {
                if (strcasecmp(headers[i].key, "Content-Length") == 0) {
                    content_length = atoi(headers[i].value);
                    break;
                }
            }

            if (content_length <= 0 || content_length > 10 * 1024 * 1024) {
                const char *msg = "HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\n\r\n";
                write(task.client_fd, msg, strlen(msg));
                shutdown(task.client_fd, SHUT_WR);
                close(task.client_fd);
                return NULL;
            }

            char *body = malloc(content_length + 1);
            if (!body) {
                //Handle memory failure
                const char *msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                write(task.client_fd, msg, strlen(msg));
                shutdown(task.client_fd, SHUT_WR);
                close(task.client_fd);
                return NULL;
            }
            // Calc how many body bytes we already have in buffer.
            int body_in_buffer = total_read - header_end;
            if (body_in_buffer > content_length)
                body_in_buffer = content_length;

            memcpy(body, buffer + header_end, body_in_buffer);

            int body_received = body_in_buffer;
            while (body_received < content_length) {
                int r = read(task.client_fd, body + body_received, content_length - body_received);
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
            return NULL; // EXIT cleanly
        }
        
        // Default to 404 if method is unsupported
        int status_code = 404;
        if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
            status_code = server_file(task.client_fd, method, path, task.client_addr, strcmp(method, "HEAD") == 0);
        } else {
            const char *msg = 
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Allow: GET, HEAD, POST\r\n"
                "Content-Length: 0\r\n\r\n";
            write(task.client_fd, msg, strlen(msg));
            status_code = 405;
        }
    
        log_request(client_ip, method, path, status_code);
        close(task.client_fd);
        }

    return NULL;
}

int main() {
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsocketopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint); // Catch Ctrl + C

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    //bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    //listen(server_fd, 10);

    log_file = fopen("access.log", "a");
    if (!log_file) {
        perror("fopen log file");
        exit(EXIT_FAILURE);
    }

    pthread_t thread_pool[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&thread_pool[i], NULL, worker_thread, NULL);
    }

    printf("Static file server running on http://localhost:%d\n", PORT);

    while (running) {
        struct pollfd pfd = {
            .fd = server_fd,
            .events = POLLIN
        };
        
            int ret = poll(&pfd, 1, 500); //Wait up to 500ms
            if (ret > 0 && (pfd.revents & POLLIN)) {
                int client_fd = accept(server_fd,(struct sockaddr*)&client_addr, &addr_len);
                if (client_fd >= 0) {
                    enqueue(client_fd, client_addr);
                } else {
                    if (running) perror("accept");
                }
            }
    }
    printf("Almost done...\n");
    close(server_fd);
       
    // Signal threads to exit by enqueuing poison pills.
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        enqueue(-1, (struct sockaddr_in){0});
    }

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(thread_pool[i], NULL);
    }
    printf("Server shutdown complete.\n");
    return 0;
}
//i need to get out, have a drink, or smthing ,idk!