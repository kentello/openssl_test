#include "ClientConnectionMgr.H"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>

using namespace TLSClientNS;

int ClientConnectioMgr::server_connect(const char* ip, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        std::string errStr("socket() error");
        errStr += std::string(strerror(errno));
        throw std::runtime_error(errStr);
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons(port);
    socklen_t socklen = sizeof(sa);
    if (connect(sock, (struct sockaddr *)&sa, socklen))
    {
        std::string errStr("connect() error");
        errStr += std::string(strerror(errno));
        throw std::runtime_error(errStr);
        return 1;
    }

    return sock;
}

void ClientConnectioMgr::secure(int sock)
{
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new (meth);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_new() error");
    }

    ssl = SSL_new (ctx);
    if (!ssl)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_new() error");
    }

    //int secureSock = SSL_get_fd(ssl);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_connect() error");
    }
}

std::string ClientConnectioMgr::recv_packet()
{
    std::string msg;
    int len = 0;
    char buf[1000];
    do
    {
        len = SSL_read(ssl, buf, 1000);
        msg += buf;
    } while (len > 0);

    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
        {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("SSL_read() error");
        }
    }

    return msg;
}

void ClientConnectioMgr::run(const char* ip, int port, std::string msg)
{
    int sock = server_connect(ip, port);
    secure(sock);
    if (SSL_write(ssl, msg.c_str(), msg.size()) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_write() error");
    }

    std::string answer = recv_packet();

    std::string result;
    std::string signature;
    parse_answer(answer, result, signature);


    EVP_MD_CTX *mdctx = NULL;
    if(!(mdctx = EVP_MD_CTX_create()))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("EVP_MD_CTX_create () error");
    }

    EVP_PKEY * key = read_secret_key_from_file("key_verify.pem");
    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_ecdsa(), NULL, key))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("EVP_DigestVerifyInit () error");
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, result.c_str(), result.size()))
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("EVP_DigestVerifyUpdate () error");
    }

    if (1 == EVP_DigestVerifyFinal(mdctx, (const unsigned char*)signature.c_str(), signature.size()))
    {
        std::cout << "Signature correct (message not corrupted)" << std::endl;
    }
    else
    {
        std::cout << "Signature incorrect (message has corrupted)" << std::endl;
    }
}
