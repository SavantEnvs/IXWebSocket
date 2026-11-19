// Fuzzes the client side of a WebSocket connection: ix::WebSocketTransport::connectToUrl on an
// already-connected socket (WebSocketHandshake::clientHandshake: status line, response headers,
// Sec-WebSocket-Accept check, permessage-deflate negotiation) and then the client-role frame parser
// in poll()/dispatch(). The input is the server's whole reply. The fake server peer reads the
// client's upgrade request first and, like a real server, substitutes the Accept value computed
// from the request's random Sec-WebSocket-Key for every "{ACCEPT}" token in the input, so frames
// after a valid handshake are reachable.
#include "fake_peer.h"
#include "ws_transport_common.h"

#include <ixwebsocket/IXSocket.h>
#include <ixwebsocket/IXWebSocketHandshakeKeyGen.h>
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
    std::thread peer(fuzzpeer::runPeer, fds[1], true, [&input](const std::string& request) {
        char accept[29] = {}; // 28 base64 chars + NUL, as upstream sizes it
        WebSocketHandshakeKeyGen::generate(fuzzpeer::headerValue(request, "Sec-WebSocket-Key"),
                                           accept);
        std::string reply = input;
        const std::string token = "{ACCEPT}";
        for (size_t pos = reply.find(token); pos != std::string::npos; pos = reply.find(token, pos))
        {
            reply.replace(pos, token.size(), accept);
            pos += 28;
        }
        return reply;
    });

    {
        std::unique_ptr<ix::Socket> socket(new ix::Socket(fds[0]));
        std::string err;
        if (socket->init(err))
        {
            ix::WebSocketTransport transport;
            transport.configure(ix::WebSocketPerMessageDeflateOptions(true), {}, true, -1, {},
                                1 << 20);
            auto result = transport.connectToUrl("ws://127.0.0.1:8008/chat", {}, 10, {},
                                                 std::move(socket));
            if (result.success) fuzzws::pump(transport);
        }
    }
    peer.join();
    return 0;
}
