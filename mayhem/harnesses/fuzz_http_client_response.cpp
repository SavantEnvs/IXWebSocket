// Fuzzes ix::HttpClient's response handling: status line, headers (parseHttpHeaders), Content-Length
// and chunked framing, gzip-encoded bodies, redirect status handling. The input is the server's whole
// reply; a fake server peer on a loopback TCP listener (HttpClient opens its own connection) reads the
// GET request, sends the input, shuts down its write side, and drains until the client closes.
// Redirects are not followed, so every exec talks to this one listener only.
#include "fake_peer.h"

#include <ixwebsocket/IXHttpClient.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>

namespace
{
    int g_listenFd = -1;
    int g_port = 0;
} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    g_listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(g_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(g_listenFd, 16) != 0)
        abort();
    socklen_t len = sizeof(addr);
    getsockname(g_listenFd, reinterpret_cast<sockaddr*>(&addr), &len);
    g_port = ntohs(addr.sin_port);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    // The client connects once per exec (no redirects, fresh client); the peer accepts it.
    std::thread peer([&input]() {
        int fd = ::accept(g_listenFd, nullptr, nullptr);
        if (fd < 0) return;
        fuzzpeer::runPeer(fd, true, [&input](const std::string&) { return input; });
    });

    {
        ix::HttpClient client;
        const std::string url = "http://127.0.0.1:" + std::to_string(g_port) + "/index.html";
        auto args = client.createRequest(url);
        args->followRedirects = false;
        args->compress = true;
        auto response = client.get(url, args);
        if (!response) __builtin_trap();
        volatile size_t sink = response->body.size() + response->headers.size() +
                               static_cast<size_t>(response->statusCode);
        (void) sink;
    }
    peer.join();
    return 0;
}
