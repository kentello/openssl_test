#pragma once

#include <atomic>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

namespace TLSServerNS
{

class ConnectionManager;

class ConnectionHandler
{
public:
    ConnectionHandler() :
        _stop_token{false}
    { }

    ConnectionHandler(ConnectionHandler &&conn_mgr_move) :
        _mgr(conn_mgr_move._mgr),
        _stop_token(conn_mgr_move._stop_token.load())
    {
        _mgr = nullptr;
    }

    void start(ConnectionManager *mgr)
    {
        if (!mgr)
        {
            std::cerr << "Incorrect pointer to ConnectionManager! Can't start new thread" << std::endl;
            return;
        }

        _mgr = mgr;
        _worker_thread = std::move(std::thread(&ConnectionHandler::process, this));
    }
    void stop()
    {
        _stop_token = true;
        if (_worker_thread.joinable())
            _worker_thread.join();
    }

private:
    void process();
    void secure_connection(int connection);
    SSL_CTX *create_context();
    void configure_context(SSL_CTX *ctx);

private:
    ConnectionManager *_mgr;
    std::atomic_bool _stop_token;
    std::thread _worker_thread;
};

} // namespace TLSServerNS
