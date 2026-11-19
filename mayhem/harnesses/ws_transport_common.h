// Shared by the WebSocket transport harnesses: drive an ix::WebSocketTransport until the peer's
// bytes are consumed. poll() returns AbnormalClose at EOF and dispatch() then closes the transport;
// the iteration bound is only a backstop against a transport that stops making progress.
#pragma once

#include <ixwebsocket/IXWebSocketTransport.h>

#include <string>

namespace fuzzws
{
    inline void pump(ix::WebSocketTransport& transport)
    {
        size_t messages = 0;
        auto onMessage = [&messages](const std::string& msg, size_t wireSize, bool decompressionError,
                                     ix::WebSocketTransport::MessageKind kind) {
            messages += msg.size() + wireSize + (decompressionError ? 1 : 0) +
                        static_cast<size_t>(kind);
        };
        for (int i = 0; i < 100000; i++)
        {
            if (transport.getReadyState() == ix::WebSocketTransport::ReadyState::CLOSED) break;
            auto result = transport.poll();
            transport.dispatch(result, onMessage);
            if (result != ix::WebSocketTransport::PollResult::Succeeded &&
                transport.getReadyState() != ix::WebSocketTransport::ReadyState::OPEN)
                break;
        }
        transport.close();
    }
} // namespace fuzzws
