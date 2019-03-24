/* (c) 2019 Mareks Malnacs
 * This code is licensed under MIT license (see LICENSE.md for details)
 */

#include <memory>
#include <cstdint>
#include <iostream>
#include <chrono>
#include <thread>
#include <functional>
#include <evhttp.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std::chrono_literals;

std::function<void(int) > shutdown_handler;

void signal_handler(int signal) {
    shutdown_handler(signal);
}

int main(int argc, char **argv) {
    struct sigaction sa;
    bzero(&sa, sizeof (sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    std::unique_ptr<struct event_base, decltype(&event_base_free) > ev(event_init(), &event_base_free);
    if (!ev) {
        std::cerr << "Failed to init libevent." << std::endl;
        return -1;
    }

    shutdown_handler = [&](int) {
        event_base_loopexit(ev.get(), NULL);
    };

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free) > ctx(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
    if (!ctx) {
        std::cerr << "Failed to create SSL context." << std::endl;
        return -1;
    }

    SSL_CTX_set_options(ctx.get(),
            SSL_OP_SINGLE_DH_USE |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free) > ecdh(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), &EC_KEY_free);
    SSL_CTX_set_tmp_ecdh(ctx.get(), ecdh.get());

    SSL_CTX_use_certificate_file(ctx.get(), "certificate.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx.get(), "key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx.get())) {
        std::cerr << "Failed to load private key file." << std::endl;
        return -1;
    }

    auto newConnCb = [] (struct event_base *base, void *arg) -> struct bufferevent * {
        SSL_CTX *ctx = (SSL_CTX *) arg;
        return bufferevent_openssl_socket_new(base,
                -1,
                SSL_new(ctx),
                BUFFEREVENT_SSL_ACCEPTING,
                BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    };


    std::unique_ptr<struct evhttp, decltype(&evhttp_free) > http(evhttp_new(ev.get()), &evhttp_free);
    if (!http) {
        std::cerr << "Failed to init http server." << std::endl;
        return -1;
    }

    evhttp_set_bevcb(http.get(), newConnCb, ctx.get());

    auto onReq = [] (evhttp_request *req, void *) {
        char *client_ip;
        u_short client_port;

        auto *buf = evhttp_request_get_output_buffer(req);
        if (!buf) return;

        evhttp_connection_get_peer(evhttp_request_get_connection(req), &client_ip, &client_port);
        std::cout << "Client IP " << client_ip << " port " << client_port << std::endl;

        evbuffer_add_printf(buf, "<html><body><p>test https server</p></body></html>");
        evhttp_send_reply(req, HTTP_OK, "OK", buf);
    };

    evhttp_set_gencb(http.get(), onReq, nullptr);

    if (evhttp_bind_socket(http.get(), "127.0.0.1", 5555))
        std::cerr << "Failed to bind to port" << std::endl;

    if (event_base_dispatch(ev.get())) {
        std::cerr << "Failed to run message loop." << std::endl;
    }

    std::cout << "Exiting." << std::endl;
    return 0;
}
