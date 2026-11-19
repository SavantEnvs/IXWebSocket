// Fuzzes the permessage-deflate extension: the Sec-WebSocket-Extensions value parser
// (ix::WebSocketPerMessageDeflateOptions(std::string)) and the message inflater
// (ix::WebSocketPerMessageDeflateDecompressor) set up with the negotiated window bits.
// Input: the extension header value up to the first '\n', then the compressed message payload.
#include <ixwebsocket/IXWebSocketPerMessageDeflateCodec.h>
#include <ixwebsocket/IXWebSocketPerMessageDeflateOptions.h>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string all(reinterpret_cast<const char*>(data), size);
    size_t nl = all.find('\n');
    std::string extension = all.substr(0, nl);
    std::string payload = nl == std::string::npos ? std::string() : all.substr(nl + 1);

    ix::WebSocketPerMessageDeflateOptions options(extension);
    std::string header = options.generateHeader();
    (void) header;
    if (!options.enabled()) return 0;

    ix::WebSocketPerMessageDeflateDecompressor decompressor;
    if (!decompressor.init(options.getClientMaxWindowBits(), options.getClientNoContextTakeover()))
        return 0;
    std::string out;
    bool limitExceeded = false;
    decompressor.decompress(payload, out, 1 << 20, &limitExceeded);
    return 0;
}
