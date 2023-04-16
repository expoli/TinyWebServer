#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H

#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cassert>
#include <sys/stat.h>
#include <cstring>
#include <pthread.h>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <cstdarg>
#include <cerrno>
#include <sys/wait.h>
#include <sys/uio.h>
#include <map>

#include "../lock/locker.h"
#include "../timer/lst_timer.h"
#include "../log/log.h"

class http_conn {
public:
    static const int FILENAME_LEN = 200;
    static const int READ_BUFFER_SIZE = 2048;
    static const int WRITE_BUFFER_SIZE = 1024;
    enum METHOD {
        GET = 0,
        POST,
        HEAD,
        PUT,
        DELETE,
        TRACE,
        OPTIONS,
        CONNECT,
        PATH
    };
    enum CHECK_STATE {
        CHECK_STATE_REQUESTLINE = 0,
        CHECK_STATE_HEADER,
        CHECK_STATE_CONTENT,
        CHECK_STATE_PROXY
    };
    enum HTTP_CODE {
        NO_REQUEST,
        GET_REQUEST,
        BAD_REQUEST,
        NO_RESOURCE,
        FORBIDDEN_REQUEST,
        FILE_REQUEST,
        INTERNAL_ERROR,
        PROXY_REQUEST,
        CLOSED_CONNECTION
    };
    enum LINE_STATUS {
        LINE_OK = 0,
        LINE_BAD,
        LINE_OPEN
    };
    /**
     * 代理端点
     */
    union ENDPOINT {
        int fd;
        struct sockaddr_in proxy_addr;
    };
    /**
     * 这个枚举类型用于表示端点类型
     * 包含了文件，CGI，用户，PUT，客户端，代理
     */
    enum ENDPOINT_TYPE {
        EP_NONE = 0,
        EP_FILE, EP_CGI, EP_USER, EP_PUT, EP_CLIENT, EP_PROXY
    };

    /**
     * 这个定义了一个结构体，用来存储一个socket的地址信息
     */
    union socket_address {
        struct sockaddr sa;
        struct sockaddr_in sin;
    #ifdef NS_ENABLE_IPV6
            struct sockaddr_in6 sin6;
    #else
            struct sockaddr sin6;
    #endif
        };

    map<string, string> m_proxy_map;

public:
    http_conn() {}

    ~http_conn() {}

public:
    http_conn * init(int sockfd, const sockaddr_in &addr, char *, int, int);

    http_conn * init(int sockfd, const sockaddr_in &addr, char *, int, int,map<string, string> &);

    void close_conn(bool real_close = true);

    void process();

    bool read_once();

    bool write();

    /**
     * 做代理请求
     */
    http_conn::HTTP_CODE process_proxy();

    sockaddr_in *get_address() {
        return &m_address;
    }

    int remove_timer_flag;
    int conn_io_done_flag;


private:
    void init();

    HTTP_CODE process_read();

    bool process_write(HTTP_CODE ret);

    HTTP_CODE parse_request_line(char *text);

    HTTP_CODE parse_headers(char *text);

    HTTP_CODE parse_content(char *text);

    HTTP_CODE do_request();

    char *get_line() { return m_read_buf + m_start_line; };

    LINE_STATUS parse_line();

    void unmap();

    bool add_response(const char *format, ...);

    bool add_content(const char *content);

    bool add_status_line(int status, const char *title);

    bool add_headers(int content_length);

    bool add_content_type();

    bool add_content_length(int content_length);

    bool add_linger();

    bool add_blank_line();

    void open_local_endpoint();

    void close_local_endpoint();

    void handle_delete(http_conn *conn, const char *path);

    int remove_directory(const char *dir);

public:
    static int m_epollfd;
    static int m_user_count;
    int m_rw_state;  //读为0, 写为1

private:
    int m_sockfd;
    sockaddr_in m_address;
    char m_read_buf[READ_BUFFER_SIZE];
    long m_read_idx;
    long m_checked_idx;
    int m_start_line;
    char m_write_buf[WRITE_BUFFER_SIZE];
    int m_write_idx;
    CHECK_STATE m_check_state;
    METHOD m_method;
    char m_real_file[FILENAME_LEN];
    char *m_url;
    char *m_version;
    char *m_host;
    string m_remote_domain;
    int m_remote_port;
    long m_content_length;
    bool m_linger;
    char *m_file_address;
    struct stat m_file_stat;
    struct iovec m_iv[2];
    int m_iv_count;

    char *m_query_string;

    char *m_string; //存储请求头数据
    int bytes_to_send;
    int bytes_have_send;
    char *m_doc_root;

    map<string, string> m_users;
    int m_TRIGMode;
    int m_close_log;

    ENDPOINT_TYPE m_endpoint_type;
    ENDPOINT m_endpoint;

    socket_address m_socket_address;

    int m_remote_socket_fd = -1;

    map<string, string> m_request_map;

    int ns_resolve2(const char *host, in_addr *ina);

    int ns_parse_address(const char *str, socket_address *sa, int *proto, int *use_ssl, char *cert, char *ca);

    http_conn *ns_connect(const char *address, void *user_data);

    void proxy_request(struct ns_connection *pc, struct mg_connection *c);

    HTTP_CODE parse_remote_address(struct sockaddr_in &remote_addr);
};

#endif
