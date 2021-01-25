#include "ConnectionHandler.H"
#include "ConnectionManager.H"
#include "MathOperationsManager.H"
#include <unistd.h>
#include <iostream>

using namespace TLSServerNS;

static const int read_bufer_size = 2048;

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

        SSL_CTX *ctx = nullptr;
        SSL *ssl = nullptr;
        EVP_MD_CTX *mdctx = nullptr;
        unsigned char** sig = nullptr;
        
        try
        {
            // шифруем соединение
            ctx = create_context();
            configure_context(ctx);
            
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, connection);

            if (SSL_accept(ssl) <= 0)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("SSL_accept error");
            }

            // читаем данные от клиента из сокета
            uint16_t read_bytes = 0;
            uint8_t read_bufer[2048];
            
            std::string read_str;
            do
            {
                memset(read_bufer, 0, read_bufer_size);
                read_bytes = SSL_read(ssl, read_bufer, read_bufer_size);
                read_str += std::string((char *)read_bufer);
            } while (read_bytes);

            // парсим команду
            // выполняем операции
            MathOperationsManager math_mgr;
            std::string math_result = math_mgr.process(read_str);
 
            // подписываем полученные результат
            if (!(mdctx = EVP_MD_CTX_create()))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("EVP_MD_CTX_create error");
            }

            EVP_PKEY * key = read_secret_key_from_file("key.pem");
            if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_ecdsa(), NULL, key))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("EVP_DigestSignInit error");
            }

            if (1 != EVP_DigestSignUpdate(mdctx, math_result.c_str(), math_result.size()))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("EVP_DigestSignUpdate error");
            }

            size_t slen = 0;
            if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("EVP_DigestSignFinal(nullptr) error");
            }

            if (!(*sig = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * (slen))))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("OPENSSL_malloc() error");
            }
            
            if (1 != EVP_DigestSignFinal(mdctx, *sig, &slen))
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("EVP_DigestSignFinal(sig) error");
            }

            std::string sent_res = "{" + math_result + ",\"signature\": \"" + std::string((char*)*sig) + "\"}";

            // записываем результат в сокет
            if (SSL_write(ssl, sent_res.c_str(), sent_res.size()) <= 0)
            {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("SSL_write() error");
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << std::endl;
        }

        // очистка
        if (ctx)
            SSL_CTX_free(ctx);

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

        if (*sig)
            OPENSSL_free(*sig);
        if (mdctx)
            EVP_MD_CTX_destroy(mdctx);

        // закрываем сокет
        close(connection);
    }
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
