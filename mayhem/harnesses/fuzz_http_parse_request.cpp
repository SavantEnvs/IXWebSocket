// Fuzzes the HTTP/1.1 server-side request parser: ix::Http::parseRequest (request line, headers via
// parseHttpHeaders, Content-Length / chunked framing, gzip request bodies). The input is the raw
// bytes a client sends; the socket is in-memory, like upstream's HttpMemorySocket (test/IXHttpTest.cpp).
#include <ixwebsocket/IXHttp.h>
#include <ixwebsocket/IXSocket.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

namespace
{
    class MemorySocket : public ix::Socket
    {
    public:
        explicit MemorySocket(const uint8_t* data, size_t size)
            : _input(reinterpret_cast<const char*>(data), size)
        {
        }
        std::ptrdiff_t recv(void* buffer, size_t length) override
        {
            const size_t n = std::min(length, _input.size() - _offset);
            std::memcpy(buffer, _input.data() + _offset, n);
            _offset += n;
            return static_cast<std::ptrdiff_t>(n); // 0 at end of input = peer closed
        }
        std::ptrdiff_t send(char* /*buffer*/, size_t length) override
        {
            return static_cast<std::ptrdiff_t>(length);
        }

    private:
        std::string _input;
        size_t _offset = 0;
    };
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::unique_ptr<ix::Socket> socket(new MemorySocket(data, size));
    auto result = ix::Http::parseRequest(socket, 10);
    if (std::get<0>(result))
    {
        ix::HttpRequestPtr request = std::get<2>(result);
        if (!request) __builtin_trap(); // success must come with a request
        volatile size_t sink = request->uri.size() + request->method.size() +
                               request->version.size() + request->body.size() +
                               request->headers.size();
        (void) sink;
    }
    return 0;
}
