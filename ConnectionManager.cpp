#include "ConnectionManager.H"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <signal.h>

using namespace TLSServerNS;

static const uint16_t WORKER_THREADS_NUM = 5;

void handle_signal(int sig)
{
    exit_sig = sig;
}

ConnectionManager::ConnectionManager() :
    _handlers(WORKER_THREADS_NUM)
{
}

void ConnectionManager::process(uint32_t port)
{
    sigset_t mask;
    sigset_t orig_mask;
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = handle_signal;

    if (sigaction(SIGTERM, &act, 0))
    {
        std::cerr << "sigaction error" << std::endl;
        return;
    }

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0)
    {
        std::cerr << "sigprocmask error" << std::endl;
        return;
    }

    for (int i = 0; i < WORKER_THREADS_NUM; ++i)
        _handlers[i].start(this);

    int sock;

    init_openssl();

    sock = create_socket(port);

    while (!exit_sig)
    {
        fd_set fds;
        int res;

        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        res = pselect(sock + 1, &fds, NULL, NULL, NULL, &orig_mask);
        if (res < 0 && errno != EINTR)
        {
            std::cerr << "Error in pselect: " << strerror(errno) << std::endl;
            continue;
        }
        else if (exit_sig)
        {
            break;
        }
        else if (res == 0)
        {
            continue;
        }

        if (FD_ISSET(sock, &fds))
        {
            struct sockaddr_in addr;
            uint len = sizeof(addr);

            int client = accept(sock, (struct sockaddr *)&addr, &len);
            if (client < 0)
            {
                std::cerr << "Unable to accept" << std::endl;
                continue;
            }

            set_connection(client);
        }
    }

    for (int i = 0; i < WORKER_THREADS_NUM; ++i)
    {
        _handlers[i].stop();
    }

    close(sock);
    cleanup_openssl();
}

int ConnectionManager::create_socket(uint32_t port)
{
    int sock = -1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        std::cerr << "Unable to create socket: " << strerror(errno) << std::endl;
        throw std::runtime_error("socket() error");
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "Unable to bind: " << strerror(errno) << std::endl;
        throw std::runtime_error("bind() error");
    }

    if (listen(sock, 1) < 0)
    {
        std::cerr << "Unable to listens: " << strerror(errno) << std::endl;
        throw std::runtime_error("listen() error");
    }

    return sock;
}

void ConnectionManager::init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void ConnectionManager::cleanup_openssl()
{
    EVP_cleanup();
}




