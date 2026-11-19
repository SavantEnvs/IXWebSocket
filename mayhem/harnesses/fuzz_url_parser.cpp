// Fuzzes ix::UrlParser::parse (both overloads) and ix::UrlParser::isSameOrigin. The input is split at
// the first NUL into two URLs (the second only feeds isSameOrigin).
#include <ixwebsocket/IXUrlParser.h>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string all(reinterpret_cast<const char*>(data), size);
    size_t nul = all.find('\0');
    std::string first = all.substr(0, nul);
    std::string second = nul == std::string::npos ? std::string() : all.substr(nul + 1);

    std::string protocol, host, path, query;
    int port = 0;
    bool isDefaultPort = false;
    ix::UrlParser::parse(first, protocol, host, path, query, port);
    ix::UrlParser::parse(second, protocol, host, path, query, port, isDefaultPort);
    ix::UrlParser::isSameOrigin(first, second);
    ix::UrlParser::isSameOrigin(first, first);
    return 0;
}
