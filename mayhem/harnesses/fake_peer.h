// Fuzz-harness helper: the remote end of a connection, played by the harness.
//
// The library under test owns one end of a socket (socketpair or loopback TCP). FakePeer runs on a
// helper thread on the OTHER end: optionally waits for the library's HTTP request header (up to
// "\r\n\r\n"), builds the reply bytes (from the fuzz input, possibly with values computed from that
// request, like a real server would), writes them, then shuts down its write side so the library
// sees EOF, and keeps draining whatever the library sends until the library closes its end.
//
// The peer reads and writes in one poll() loop so neither side can deadlock on a full socket
// buffer, however large the input. It has no timeout: EOF always comes, because the peer always
// shuts its write side down and the harness always closes the library's end before join().
#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <functional>
#include <string>
#include <thread>

namespace fuzzpeer
{
    using MakeReply = std::function<std::string(const std::string& request)>;

    inline void runPeer(int fd, bool waitForRequest, MakeReply makeReply)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        std::string request;
        std::string pending;
        size_t offset = 0;
        bool haveReply = false;
        bool shutDown = false;

        if (!waitForRequest)
        {
            pending = makeReply(std::string());
            haveReply = true;
        }

        char buf[16384];
        while (true)
        {
            if (haveReply && !shutDown && offset == pending.size())
            {
                ::shutdown(fd, SHUT_WR);
                shutDown = true;
            }

            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN;
            if (haveReply && !shutDown) pfd.events |= POLLOUT;
            pfd.revents = 0;
            if (::poll(&pfd, 1, -1) < 0)
            {
                if (errno == EINTR) continue;
                break;
            }

            if (pfd.revents & (POLLIN | POLLHUP | POLLERR))
            {
                ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n == 0) break; // library closed its end
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                    break;
                }
                if (!haveReply)
                {
                    request.append(buf, static_cast<size_t>(n));
                    if (request.find("\r\n\r\n") != std::string::npos)
                    {
                        pending = makeReply(request);
                        haveReply = true;
                    }
                }
            }

            if (haveReply && !shutDown && (pfd.revents & POLLOUT))
            {
                ssize_t n = ::send(fd, pending.data() + offset, pending.size() - offset, MSG_NOSIGNAL);
                if (n > 0)
                    offset += static_cast<size_t>(n);
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    break;
            }
        }
        ::close(fd);
    }

    // Case-insensitive lookup of one header value in a raw HTTP request.
    inline std::string headerValue(const std::string& request, const std::string& name)
    {
        size_t pos = 0;
        while (true)
        {
            size_t eol = request.find("\r\n", pos);
            if (eol == std::string::npos || eol == pos) return std::string();
            std::string line = request.substr(pos, eol - pos);
            size_t colon = line.find(':');
            if (colon == name.size())
            {
                bool same = true;
                for (size_t i = 0; i < colon && same; i++)
                    same = ::tolower(static_cast<unsigned char>(line[i])) ==
                           ::tolower(static_cast<unsigned char>(name[i]));
                if (same)
                {
                    size_t v = colon + 1;
                    while (v < line.size() && (line[v] == ' ' || line[v] == '\t')) v++;
                    return line.substr(v);
                }
            }
            pos = eol + 2;
        }
    }
} // namespace fuzzpeer
