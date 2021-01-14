#include "ConnectionHandler.H"
#include "ConnectionManager.H"
#include <unistd.h>
#include <iostream>

using namespace TLSServerNS;

void ConnectionHandler::process()
{
    while (!_stop_token)
    {
        int connection = _mgr->get_next_connection();
        if (connection < 0)
        {
            usleep(200);
            continue;
        }

        try
        {
            // шифруем соединение
            secure_connection(connection);

            // читаем данные от клиента из сокета

            // выполняем операции

            // подписываем полученные результат

            // записываем результат в сокет
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << std::endl;
        }

        // закрываем сокет
    }
}

// TODO
void ConnectionHandler::secure_connection(int connection)
{
    (void)connection;
}


SSL_CTX* ConnectionHandler::create_context()
{
    SSL_CTX *ctx;
    const SSL_METHOD* method = TLSv1_2_client_method();
    if (!method)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("TLSv1_2_client_method() error");
    }

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_new() error");
    }

    return ctx;
}

void ConnectionHandler::configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_use_certificate_file() error");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("SSL_CTX_use_PrivateKey_file() error");
    }
}
