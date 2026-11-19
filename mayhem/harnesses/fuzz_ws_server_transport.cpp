// Fuzzes the server side of a WebSocket connection: ix::WebSocketTransport::connectToSocket
// (WebSocketHandshake::serverHandshake: request line, headers, Sec-WebSocket-Key/Version,
// permessage-deflate negotiation) and then the frame parser in poll()/dispatch() (fragmentation,
// masking, control frames, close codes, UTF-8 validation, inflate). The input is everything the
// client sends, written by a fake peer on the other end of a socketpair; the transport needs a
// real fd because poll() uses poll(2).
#include "fake_peer.h"
#include "ws_transport_common.h"

#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflateOptions.h>

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;
    std::thread peer(fuzzpeer::runPeer, fds[1], false,
                     [&input](const std::string&) { return input; });

    {
        std::unique_ptr<ix::Socket> socket(new ix::Socket(fds[0]));
        std::string err;
        if (socket->init(err))
        {
            ix::WebSocketTransport transport;
            transport.configure(ix::WebSocketPerMessageDeflateOptions(true), {}, true, -1, {},
                                1 << 20);
            auto result = transport.connectToSocket(std::move(socket), 10, true);
            if (result.success) fuzzws::pump(transport);
        }
        // transport/socket destructors close fds[0]: the peer then sees EOF
    }
    peer.join();
    return 0;
}
