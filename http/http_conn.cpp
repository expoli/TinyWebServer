#include "http_conn.h"

#include <mysql/mysql.h>
#include <fstream>
#include <dirent.h>
#include <pcap/socket.h>

typedef int sock_t;
#define closesocket(x) close(x)
#define NS_VPRINTF_BUFFER_SIZE      500
/**
 * 这个结构体用于存储静态的mime类型
 */
static const struct {
    const char *extension;
    size_t ext_len;
    const char *mime_type;
} static_builtin_mime_types[] = {
        {".html", 5, "text/html"},
        {".htm", 4, "text/html"},
        {".shtm", 5, "text/html"},
        {".shtml", 6, "text/html"},
        {".css", 4, "text/css"},
        {".js",  3, "application/javascript"},
        {".ico", 4, "image/x-icon"},
        {".gif", 4, "image/gif"},
        {".jpg", 4, "image/jpeg"},
        {".jpeg", 5, "image/jpeg"},
        {".png", 4, "image/png"},
        {".svg", 4, "image/svg+xml"},
        {".txt", 4, "text/plain"},
        {".torrent", 8, "application/x-bittorrent"},
        {".wav", 4, "audio/x-wav"},
        {".mp3", 4, "audio/x-mp3"},
        {".mid", 4, "audio/mid"},
        {".m3u", 4, "audio/x-mpegurl"},
        {".ogg", 4, "application/ogg"},
        {".ram", 4, "audio/x-pn-realaudio"},
        {".xml", 4, "text/xml"},
        {".json",  5, "application/json"},
        {".xslt", 5, "application/xml"},
        {".xsl", 4, "application/xml"},
        {".ra",  3, "audio/x-pn-realaudio"},
        {".doc", 4, "application/msword"},
        {".exe", 4, "application/octet-stream"},
        {".zip", 4, "application/x-zip-compressed"},
        {".xls", 4, "application/excel"},
        {".tgz", 4, "application/x-tar-gz"},
        {".tar", 4, "application/x-tar"},
        {".gz",  3, "application/x-gunzip"},
        {".arj", 4, "application/x-arj-compressed"},
        {".rar", 4, "application/x-rar-compressed"},
        {".rtf", 4, "application/rtf"},
        {".pdf", 4, "application/pdf"},
        {".swf", 4, "application/x-shockwave-flash"},
        {".mpg", 4, "video/mpeg"},
        {".webm", 5, "video/webm"},
        {".mpeg", 5, "video/mpeg"},
        {".mov", 4, "video/quicktime"},
        {".mp4", 4, "video/mp4"},
        {".m4v", 4, "video/x-m4v"},
        {".asf", 4, "video/x-ms-asf"},
        {".avi", 4, "video/x-msvideo"},
        {".bmp", 4, "image/bmp"},
        {".ttf", 4, "application/x-font-ttf"},
        {NULL,  0, NULL}
};

//定义http响应的一些状态信息
const char *ok_200_title = "OK";
const char *error_400_title = "Bad Request";
const char *error_400_form = "Your request has bad syntax or is inherently impossible to staisfy.\n";
const char *error_403_title = "Forbidden";
const char *error_403_form = "You do not have permission to get file form this server.\n";
const char *error_404_title = "Not Found";
const char *error_404_form = "The requested file was not found on this server.\n";
const char *error_500_title = "Internal Error";
const char *error_500_form = "There was an unusual problem serving the request file.\n";

const int MAX_PATH_SIZE = 8192;

locker m_lock;
map<string, string> users;

//对文件描述符设置非阻塞
int setnonblocking(int fd) {
    int old_option = fcntl(fd, F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd, F_SETFL, new_option);
    return old_option;
}

//将内核事件表注册读事件，ET模式，选择开启EPOLLONESHOT
void addfd(int epollfd, int fd, bool one_shot, int TRIGMode) {
    epoll_event event;
    event.data.fd = fd;
    // ET模式
    if (1 == TRIGMode)
        event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    else
        event.events = EPOLLIN | EPOLLRDHUP;

    if (one_shot)
        event.events |= EPOLLONESHOT;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
    setnonblocking(fd);
}

//从内核时间表删除描述符
void removefd(int epollfd, int fd) {
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, 0);
    close(fd);
}

//将事件重置为EPOLLONESHOT
void modfd(int epollfd, int fd, int ev, int TRIGMode) {
    epoll_event event;
    event.data.fd = fd;

    if (1 == TRIGMode)
        event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    else
        event.events = ev | EPOLLONESHOT | EPOLLRDHUP;

    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event);
}

int http_conn::m_user_count = 0;
int http_conn::m_epollfd = -1;

//关闭连接，关闭一个连接，客户总量减一
void http_conn::close_conn(bool real_close) {
    if (real_close && (m_sockfd != -1)) {
        printf("close %d\n", m_sockfd);
        removefd(m_epollfd, m_sockfd);
        m_sockfd = -1;
        m_user_count--;
    }
}

//初始化连接,外部调用初始化套接字地址
http_conn * http_conn::init(int sockfd, const sockaddr_in &addr, char *root, int TRIGMode,
                     int close_log) {
    m_sockfd = sockfd;
    m_address = addr;

    addfd(m_epollfd, sockfd, true, m_TRIGMode);
    m_user_count++;

    //当浏览器出现连接重置时，可能是网站根目录出错或http响应格式出错或者访问的文件中内容完全为空
    m_doc_root = root;
    m_TRIGMode = TRIGMode;
    m_close_log = close_log;

    init();
}

//初始化连接,外部调用初始化套接字地址
http_conn * http_conn::init(int sockfd, const sockaddr_in &addr, char *root, int TRIGMode,
                            int close_log, map<string, string> &proxy_map) {
    m_sockfd = sockfd;
    m_address = addr;

    addfd(m_epollfd, sockfd, true, m_TRIGMode);
    m_user_count++;

    //当浏览器出现连接重置时，可能是网站根目录出错或http响应格式出错或者访问的文件中内容完全为空
    m_doc_root = root;
    m_TRIGMode = TRIGMode;
    m_close_log = close_log;

    m_proxy_map = proxy_map;

    init();
}

//初始化新接受的连接
//check_state默认为分析请求行状态
void http_conn::init() {
    bytes_to_send = 0;
    bytes_have_send = 0;
    m_check_state = CHECK_STATE_REQUESTLINE;
    m_linger = false;
    m_method = GET;
    m_url = 0;
    m_version = 0;
    m_content_length = 0;
    m_host = 0;
    m_start_line = 0;
    m_checked_idx = 0;
    m_read_idx = 0;
    m_write_idx = 0;
    m_rw_state = 0;
    remove_timer_flag = 0;
    conn_io_done_flag = 0;

    memset(m_read_buf, '\0', READ_BUFFER_SIZE);
    memset(m_write_buf, '\0', WRITE_BUFFER_SIZE);
    memset(m_real_file, '\0', FILENAME_LEN);
}

//从状态机，用于分析出一行内容
//返回值为行的读取状态，有LINE_OK,LINE_BAD,LINE_OPEN
http_conn::LINE_STATUS http_conn::parse_line() {
    char temp;
    for (; m_checked_idx < m_read_idx; ++m_checked_idx) {
        temp = m_read_buf[m_checked_idx];
        if (temp == '\r') {
            if ((m_checked_idx + 1) == m_read_idx)
                return LINE_OPEN;
            else if (m_read_buf[m_checked_idx + 1] == '\n') {
                m_read_buf[m_checked_idx++] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        } else if (temp == '\n') {
            if (m_checked_idx > 1 && m_read_buf[m_checked_idx - 1] == '\r') {
                m_read_buf[m_checked_idx - 1] = '\0';
                m_read_buf[m_checked_idx++] = '\0';
                return LINE_OK;
            }
            return LINE_BAD;
        }
    }
    return LINE_OPEN;
}

//循环读取客户数据，直到无数据可读或对方关闭连接
//非阻塞ET工作模式下，需要一次性将数据读完
bool http_conn::read_once() {
    if (m_read_idx >= READ_BUFFER_SIZE) {
        return false;
    }
    int bytes_read = 0;

    //LT读取数据
    if (0 == m_TRIGMode) {
        bytes_read = recv(m_sockfd, m_read_buf + m_read_idx, READ_BUFFER_SIZE - m_read_idx, 0);
        m_read_idx += bytes_read;

        if (bytes_read <= 0) {
            return false;
        }

        return true;
    }
        //ET读数据
    else {
        while (true) {
            bytes_read = recv(m_sockfd, m_read_buf + m_read_idx, READ_BUFFER_SIZE - m_read_idx, 0);
            if (bytes_read == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                return false;
            } else if (bytes_read == 0) {
                return false;
            }
            m_read_idx += bytes_read;
        }
        return true;
    }
}

//解析http请求行，获得请求方法，目标url及http版本号
http_conn::HTTP_CODE http_conn::parse_request_line(char *text) {
    m_url = strpbrk(text, " \t");
    if (!m_url) {
        return BAD_REQUEST;
    }
    *m_url++ = '\0';
    char *method = text;
    if (strcasecmp(method, "GET") == 0)
        m_method = GET;
    else if (strcasecmp(method, "POST") == 0) {
        m_method = POST;
    } else
        return BAD_REQUEST;
    m_url += strspn(m_url, " \t");
    m_version = strpbrk(m_url, " \t");
    if (!m_version)
        return BAD_REQUEST;
    *m_version++ = '\0';
    m_version += strspn(m_version, " \t");
    if (strcasecmp(m_version, "HTTP/1.1") != 0)
        return BAD_REQUEST;
    if (strncasecmp(m_url, "http://", 7) == 0) {
        m_url += 7;
        m_url = strchr(m_url, '/');
    }

    if (strncasecmp(m_url, "https://", 8) == 0) {
        m_url += 8;
        m_url = strchr(m_url, '/');
    }

    if (!m_url || m_url[0] != '/')
        return BAD_REQUEST;
    //当url为/时，显示判断界面
    if (strlen(m_url) == 1)
        strcat(m_url, "index.html");
    m_check_state = CHECK_STATE_HEADER;
    return NO_REQUEST;
}

//解析http请求的一个头部信息
http_conn::HTTP_CODE http_conn::parse_headers(char *text) {
    /**
     * 头解析完成
     */

    char *key = nullptr;
    char *value = nullptr;
    if (text[0] == '\0') {
        if (m_method == POST && m_content_length != 0) {
            m_check_state = CHECK_STATE_CONTENT;
            m_endpoint_type = EP_CGI;
            return NO_REQUEST;
        }
        if (m_proxy_map.find(m_remote_domain) != m_proxy_map.end()) {
            m_check_state = CHECK_STATE_PROXY;
            m_endpoint_type = EP_PROXY;
            return PROXY_REQUEST;
        }
        return GET_REQUEST;
    } else if (strncasecmp(text, "Connection:", 11) == 0) {
        key = text;
        text += 11;
        text += strspn(text, " \t");
        *(key+(text-key)-1) = '\0';
        if (strcasecmp(text, "keep-alive") == 0) {
            m_linger = true;
        }
        value = text;
        m_request_map[key] = value;
    } else if (strncasecmp(text, "Content-length:", 15) == 0) {
        key = text;
        text += 15;
        text += strspn(text, " \t");
        *(key+(text-key)-1) = '\0';
        m_content_length = atol(text);
        value = text;
        m_request_map[key] = value;
    } else if (strncasecmp(text, "Host:", 5) == 0) {
        key = text;
        text += 5;
        text += strspn(text, " \t");
        *(key+(text-key)-1) = '\0';
        m_host = text;
        value = text;
        m_request_map[key] = value;
        char domain[128] ;
        memset(domain, 0, sizeof(domain));
        strncpy(domain, m_host, strchr(m_host, ':')-m_host);
        m_remote_domain = domain;
        m_remote_port = atoi(strchr(m_host, ':') + 1);
        // todo 在解析请求头的时候查看 host 字段是否在目标代理中（如何传递？）可以暂时放在连接中
    } else {
        key = text;
        text = (char *)memchr(text,':', strlen(text));
        if (text == nullptr) {
            return BAD_REQUEST;
        }
        text += 1;
        text += strspn(text, " \t");
        *(key+(text-key)-1) = '\0';
        value = text;
        m_request_map[key] = value;
    }
    return NO_REQUEST;
}

//判断http请求是否被完整读入
http_conn::HTTP_CODE http_conn::parse_content(char *text) {
    if (m_read_idx >= (m_content_length + m_checked_idx)) {
        text[m_content_length] = '\0';
        //POST请求中最后为输入的用户名和密码
        m_string = text;
        return GET_REQUEST;
    }
    return NO_REQUEST;
}

/**
 * 读操作主状态机
 * @return
 */
http_conn::HTTP_CODE http_conn::process_read() {
    LINE_STATUS line_status = LINE_OK;
    HTTP_CODE ret = NO_REQUEST;
    char *text = 0;

    while ((m_check_state == CHECK_STATE_CONTENT && line_status == LINE_OK) ||
    (m_check_state == CHECK_STATE_PROXY && line_status == LINE_OK) ||
           ((line_status = parse_line()) == LINE_OK)) {
        text = get_line();
        m_start_line = m_checked_idx;
        LOG_INFO("%s", text);
        switch (m_check_state) {
            // 解析请求行
            case CHECK_STATE_REQUESTLINE: {
                ret = parse_request_line(text);
                if (ret == BAD_REQUEST)
                    return BAD_REQUEST;
                break;
            }
            case CHECK_STATE_HEADER: {
                ret = parse_headers(text);
                if (ret == BAD_REQUEST)
                    return BAD_REQUEST;
                else if (ret == GET_REQUEST) {
                    return do_request();
                }
                break;
            }
            case CHECK_STATE_PROXY:{
                ret = process_proxy();
                break;
            }
            case CHECK_STATE_CONTENT: {
                ret = parse_content(text);
                if (ret == GET_REQUEST)
                    return do_request();
                line_status = LINE_OPEN;
                break;
            }
            default:
                return INTERNAL_ERROR;
        }
    }
    return NO_REQUEST;
}

http_conn::HTTP_CODE http_conn::do_request() {
    strcpy(m_real_file, m_doc_root);
    int len = strlen(m_doc_root);
    //printf("m_url:%s\n", m_url);
    const char *p = strrchr(m_url, '/');

    /**
     * 如果请求资源路径为/,则默认请求主页index.html
     */
    if (strcmp(m_url,"/")==0) {
        char *m_url_real = (char *) malloc(sizeof(char) * 30);
        strcpy(m_url_real, "/index.html");
        strncpy(m_real_file + len, m_url_real, strlen(m_url_real));

        free(m_url_real);
    } else  // 否则将请求资源路径与网站根目录相结合
        strncpy(m_real_file + len, m_url, FILENAME_LEN - len - 1);

    if (stat(m_real_file, &m_file_stat) < 0)
        return NO_RESOURCE;

    if (!(m_file_stat.st_mode & S_IROTH))
        return FORBIDDEN_REQUEST;

    if (S_ISDIR(m_file_stat.st_mode))
        return BAD_REQUEST;

    int fd = open(m_real_file, O_RDONLY);
    m_file_address = (char *) mmap(0, m_file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    return FILE_REQUEST;
}

void http_conn::unmap() {
    if (m_file_address) {
        munmap(m_file_address, m_file_stat.st_size);
        m_file_address = 0;
    }
}

bool http_conn::write() {
    int temp = 0;

    if (bytes_to_send == 0) {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        init();
        return true;
    }

    while (1) {
        temp = writev(m_sockfd, m_iv, m_iv_count);

        if (temp < 0) {
            if (errno == EAGAIN) {
                modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
                return true;
            }
            unmap();
            return false;
        }

        bytes_have_send += temp;
        bytes_to_send -= temp;
        if (bytes_have_send >= m_iv[0].iov_len) {
            m_iv[0].iov_len = 0;
            m_iv[1].iov_base = m_file_address + (bytes_have_send - m_write_idx);
            m_iv[1].iov_len = bytes_to_send;
        } else {
            m_iv[0].iov_base = m_write_buf + bytes_have_send;
            m_iv[0].iov_len = m_iv[0].iov_len - bytes_have_send;
        }

        if (bytes_to_send <= 0) {
            unmap();
            modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);

            if (m_linger) {
                init();
                return true;
            } else {
                return false;
            }
        }
    }
}

bool http_conn::add_response(const char *format, ...) {
    if (m_write_idx >= WRITE_BUFFER_SIZE)
        return false;
    va_list arg_list;
    va_start(arg_list, format);
    int len = vsnprintf(m_write_buf + m_write_idx, WRITE_BUFFER_SIZE - 1 - m_write_idx, format, arg_list);
    if (len >= (WRITE_BUFFER_SIZE - 1 - m_write_idx)) {
        va_end(arg_list);
        return false;
    }
    m_write_idx += len;
    va_end(arg_list);

    LOG_INFO("request:%s", m_write_buf);

    return true;
}

bool http_conn::add_status_line(int status, const char *title) {
    return add_response("%s %d %s\r\n", "HTTP/1.1", status, title);
}

bool http_conn::add_headers(int content_len) {
    return add_content_length(content_len) && add_linger() &&
           add_blank_line();
}

bool http_conn::add_content_length(int content_len) {
    return add_response("Content-Length:%d\r\n", content_len);
}

bool http_conn::add_content_type() {
    return add_response("Content-Type:%s\r\n", "text/html");
}

bool http_conn::add_linger() {
    return add_response("Connection:%s\r\n", (m_linger == true) ? "keep-alive" : "close");
}

bool http_conn::add_blank_line() {
    return add_response("%s", "\r\n");
}

bool http_conn::add_content(const char *content) {
    return add_response("%s", content);
}

bool http_conn::process_write(HTTP_CODE ret) {
    switch (ret) {
        case INTERNAL_ERROR: {
            add_status_line(500, error_500_title);
            add_headers(strlen(error_500_form));
            if (!add_content(error_500_form))
                return false;
            break;
        }
        /**
         * 此处应该进行无资源响应
         */
        case NO_RESOURCE: {
            add_status_line(404, error_404_title);
            add_headers(strlen(error_404_form));
            if (!add_content(error_404_form))
                return false;
            break;
        }
        case FORBIDDEN_REQUEST: {
            add_status_line(403, error_403_title);
            add_headers(strlen(error_403_form));
            if (!add_content(error_403_form))
                return false;
            break;
        }
        case FILE_REQUEST: {
            add_status_line(200, ok_200_title);
            if (m_file_stat.st_size != 0) {
                add_headers(m_file_stat.st_size);
                m_iv[0].iov_base = m_write_buf;
                m_iv[0].iov_len = m_write_idx;
                m_iv[1].iov_base = m_file_address;
                m_iv[1].iov_len = m_file_stat.st_size;
                m_iv_count = 2;
                bytes_to_send = m_write_idx + m_file_stat.st_size;
                return true;
            } else {
                const char *ok_string = "<html><body></body></html>";
                add_headers(strlen(ok_string));
                if (!add_content(ok_string))
                    return false;
            }
        }
        case PROXY_REQUEST:{
            add_status_line(200, ok_200_title);
            if (m_request_map.empty()){

            }
        }
        default:
            return false;
    }
    m_iv[0].iov_base = m_write_buf;
    m_iv[0].iov_len = m_write_idx;
    m_iv_count = 1;
    bytes_to_send = m_write_idx;
    return true;
}
/**
 * 数据从 socket 读取到缓冲区后第一步执行的动作
 */
void http_conn::process() {
    HTTP_CODE read_ret = process_read();
    if (read_ret == NO_REQUEST) {
        modfd(m_epollfd, m_sockfd, EPOLLIN, m_TRIGMode);
        return;
    }
    bool write_ret = process_write(read_ret);
    if (!write_ret) {
        close_conn();
    }
    modfd(m_epollfd, m_sockfd, EPOLLOUT, m_TRIGMode);
}
// reverse proxy function
http_conn::HTTP_CODE http_conn::process_proxy() {
    string remote_domain = m_proxy_map[m_remote_domain];
    if (remote_domain.empty()) {
        return BAD_REQUEST;
    }
    int remote_port = 80;

    // parse remote domain and port
    std::size_t found = remote_domain.find(':');
    if (found != std::string::npos) {
        remote_port = atoi(remote_domain.substr(found + 1).c_str());
        remote_domain = remote_domain.substr(0, found);
    }
    m_remote_domain = remote_domain;
    m_remote_port = remote_port;

    // parse remote address to sockaddr_in
    struct sockaddr_in remote_addr{};
    if (parse_remote_address(remote_addr) == BAD_REQUEST) {
        return BAD_REQUEST;
    }

    m_endpoint_type = EP_PROXY;
    m_endpoint.proxy_addr = remote_addr;
    int remote_sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (remote_sockfd < 0) {
        return BAD_REQUEST;
    }
    if (connect(remote_sockfd, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) < 0) {
        return BAD_REQUEST;
    }
    m_remote_socket_fd = remote_sockfd;
    // todo send request to remote server
    // 准备数据
    if (m_request_map.empty()){

    }
    process_write(PROXY_REQUEST);
}

http_conn::HTTP_CODE http_conn::parse_remote_address(struct sockaddr_in &remote_addr){
    struct hostent *remote_host = gethostbyname(m_remote_domain.c_str());
    if (remote_host == nullptr) {
        return BAD_REQUEST;
    }
    bzero(&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(m_remote_port);
    remote_addr.sin_addr = *((struct in_addr *) remote_host->h_addr);

    return PROXY_REQUEST;
}

//
//int forward(http_conn *c, const char *addr) {
//    static const char ok[] = "HTTP/1.1 200 OK\r\n\r\n";
//    http_conn *conn = (http_conn *) c;
//    struct ns_connection *pc;
//
//    if ((pc = ns_connect(&conn->server->ns_mgr, addr,
//                         mg_ev_handler, conn)) == NULL) {
//        conn->ns_conn->flags |= NSF_CLOSE_IMMEDIATELY;
//        return 0;
//    }
//
//    // Interlink two connections
//    pc->flags |= MG_PROXY_CONN;
//    conn->endpoint_type = EP_PROXY;
//    conn->endpoint.nc = pc;
//    DBG(("%p [%s] [%s] -> %p %p", conn, c->uri, addr, pc, conn->ns_conn->ssl));
//
//    if (strcmp(c->request_method, "CONNECT") == 0) {
//        // For CONNECT request, reply with 200 OK. Tunnel is established.
//        // TODO(lsm): check for send() failure
//        (void) send(conn->ns_conn->sock, ok, sizeof(ok) - 1, 0);
//    } else {
//        // Strip "http://host:port" part from the URI
//        if (memcmp(c->uri, "http://", 7) == 0) c->uri += 7;
//        while (*c->uri != '\0' && *c->uri != '/') c->uri++;
//        proxy_request(pc, c);
//    }
//    return 1;
//}
//
/**
 * 用于设置 socket 为非阻塞模式
 * @param sock
 */
static void ns_set_non_blocking_mode(sock_t sock) {
#ifdef _WIN32
    unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int ns_is_error(int n) {
    return n == 0 ||
           (n < 0 && errno != EINTR && errno != EINPROGRESS &&
            errno != EAGAIN && errno != EWOULDBLOCK
#ifdef _WIN32
            && WSAGetLastError() != WSAEINTR && WSAGetLastError() != WSAEWOULDBLOCK
#endif
    );
}

/**
 * 连接到指定的地址并返回一个连接对象
 * @param mgr
 * @param address
 * @param callback
 * @param user_data
 * @return
 */
http_conn*  http_conn::ns_connect(const char *address, void *user_data) {
    int sock = INVALID_SOCKET;
    http_conn *nc = nullptr;
    sockaddr_in sa{};
    char cert[100], ca_cert[100];
    int rc, use_ssl, proto;

    ns_parse_address(address, &sa, &proto, &use_ssl, cert, ca_cert);
    if ((sock = socket(AF_INET, proto, 0)) == INVALID_SOCKET) {
        return nullptr;
    }
    ns_set_non_blocking_mode(sock);
    rc = (proto == SOCK_DGRAM) ? 0 : connect(sock, &sa.sa, sizeof(sa.sin));

    if (rc != 0 && ns_is_error(rc)) {
        closesocket(sock);
        return nullptr;
    } else if ((nc = http_conn::init(sock,sa,m_doc_root,m_TRIGMode,m_close_log))) {
        closesocket(sock);
        return nullptr;
    }

    m_socket_address = sa;

    return nc;
}
