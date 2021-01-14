#pragma once

#include "ConnectionHandler.H"

#include <queue>
#include <mutex>
#include <vector>

namespace TLSServerNS
{

static int exit_sig = 0;

class ConnectionManager
{

public:
    ConnectionManager();
    void process(uint32_t port);

    int get_next_connection()
    {
        const std::lock_guard<std::mutex> lock(_conn_mux);
        if (!_connections.size())
            return -1;

        int res = _connections.front();
        _connections.pop();
        return res;
    }

private:
    void init_openssl();
    void cleanup_openssl();
    int create_socket(uint32_t port);

    void set_connection(int conn)
    {
        const std::lock_guard<std::mutex> lock(_conn_mux);
        _connections.push(conn);
    }

private:
    std::queue<int> _connections;
    std::mutex _conn_mux;
    std::vector<ConnectionHandler> _handlers;
};

}   // namespace TLSServerNS
