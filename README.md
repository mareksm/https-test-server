# https-test-server
libevent based C++17 https test server harness

Generate private/public keys:

openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Build the test server:

cc -std=c++17 -g -o server server.cpp -DEVENT__HAVE_OPENSSL \
    -lssl -lcrypto -levent -levent_openssl -lc++
