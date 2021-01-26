#include "ClientConnectionMgr.H"
#include <iostream>
#include <fstream> 
#include <sstream>

int main(int argc, char const *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Incorrect usage! Use: \'client PATH_TO_FILE SERVER_IP SERVER_PORT\'" << std::endl;
        return 1;
    }

    std::ifstream ifs;
    ifs.open(argv[1]);
    std::stringstream strBuffer;
    strBuffer << ifs.rdbuf();
    if (!strBuffer.str().size())
    {
        std::cerr << "Empty file" << std::endl;
        return 1;
    }

    uint32_t port = 0;
    try
    {
        port = std::stoul(argv[3]);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Conversion error: " << e.what() << std::endl;
        return 1;
    }

    TLSClientNS::ClientConnectioMgr clientMgr;
    try
    {
        clientMgr.run(argv[2], port, strBuffer.str());
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}