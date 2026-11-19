// Fuzzes the SOCKS5 client: ix::Socks5::connect parsing the proxy's method-selection,
// username/password-auth and CONNECT replies. The input's first byte picks the client options
// (bit 0: offer username/password auth; bit 1: local DNS mode with an IP target), the rest is
// what the proxy sends back, written by a fake peer on the other end of a socketpair.
#include "fake_peer.h"

#include <ixwebsocket/IXProxyOptions.h>
#include <ixwebsocket/IXSocks5.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1) return -1;
    const uint8_t mode = data[0];
    std::string reply(reinterpret_cast<const char*>(data + 1), size - 1);

    ix::ProxyOptions options;
    options.host = "127.0.0.1";
    options.port = 1080;
    if (mode & 1)
    {
        options.username = "user";
        options.password = "secret";
    }
    options.dnsMode = (mode & 2) ? ix::ProxyOptions::DnsMode::Local : ix::ProxyOptions::DnsMode::Remote;
    const std::string target = (mode & 2) ? "127.0.0.1" : "example.com";

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;
    std::thread peer(fuzzpeer::runPeer, fds[1], false,
                     [&reply](const std::string&) { return reply; });

    std::string error;
    ix::Socks5::connect(fds[0], target, 80, options, error, []() { return false; });
    ::close(fds[0]);
    peer.join();
    return 0;
}
