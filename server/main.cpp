#include "ConnectionManager.H"
#include <stdint.h>
#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Incorrect usage. Use: \"server PORT\"" << std::endl;
        return 1;
    }

    uint32_t port = 0;
    try
    {
        port = std::stoul(argv[1]);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Conversion error: " << e.what() << std::endl;
    }

    TLSServerNS::ConnectionManager cMgr;
    try
    {
        cMgr.process(port);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }

    std::cout << "Exit" << std::endl << std::flush;

    return 0;
}