#pragma once

#include <string>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace TLSClientNS
{
class ClientConnectioMgr
{
public:
    ClientConnectioMgr() :
        ctx(nullptr),
        ssl(nullptr)
    { }

    ~ClientConnectioMgr()
    {
        if (ctx)
            SSL_CTX_free(ctx);

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    void run(const char* ip, int port, std::string msg);

private:
    int server_connect(const char* ip, int port);
    void secure(int socket);
    std::string recv_packet();
    std::string parse_answer(const std::string& answer, std::string& result, std::string& signature)
    {
         // TODO
         std::string res;
         return res;
    }

    EVP_PKEY *read_secret_key_from_file(const char *fname)
    {
        EVP_PKEY *key = NULL;
        FILE *fp = fopen(fname, "r");
        if (!fp)
        {
            std::cerr << "fopen " << fname << std::endl;
            throw std::runtime_error("read_secret_key_from_file(fopen)");
        }
        
        key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        if (!key)
        {
            fclose(fp);
            throw std::runtime_error("read_secret_key_from_file(PEM_read_PrivateKey)");
        }

        fclose(fp);
        return key;
    }

private:
    SSL_CTX *ctx;
    SSL *ssl;
};
}
