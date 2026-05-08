import sys
import threading
import socket
import ssl
import time
import select
import errno
from watchdog.observers import Observer
from src.filter_modules import import_modules
from src.classes import ModuleWatchdog, Service
from src.stream import TCPStream, HTTPStream
import src.constants as constants
import os
import src.utils as utils
import src.ssl_utils as ssl_utils

def get_address_family(host):
    try:
        result = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return result[0][0]
    except socket.gaierror as e:
        print(f"Error resolving host: {e}")
        return None

def service_function(service: Service, global_config, count):
    in_module, out_module = import_modules(service.name, False)

    # this event handler will reload modules on changes
    watchdog_handler = ModuleWatchdog(regexes=[f".*{service.name}.*\.py"], in_module=in_module,
                                    out_module=out_module, name=service.name)
    observer = Observer()
    observer.schedule(watchdog_handler, path=os.path.join(constants.MODULES_PATH, service.name), recursive=False)
    observer.start()

    # this is the socket we will listen on for incoming connections
    proxy_socket = socket.socket(get_address_family(service.listen_ip), socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        proxy_socket.bind((service.listen_ip, service.listen_port))
    except socket.error as e:
        print(e.strerror)
        sys.exit(5)
    proxy_socket.listen(100)
    utils.vprint(service.__dict__, global_config["verbose"])

    # endless loop until ctrl+c
    try:
        while True:
            in_socket, in_addrinfo = proxy_socket.accept()
            utils.vprint(f'Connection from {in_addrinfo[0]},{in_addrinfo[1]}', global_config["verbose"])
            proxy_thread = threading.Thread(target=connection_thread,
                                            args=(
                                                in_socket, service, global_config,
                                                watchdog_handler, count
                                            ))
            utils.vprint("Starting proxy thread " +
                         proxy_thread.name, global_config["verbose"])
            proxy_thread.start()

    except KeyboardInterrupt:
        utils.vprint('Ctrl+C detected, exiting...', global_config["verbose"])
        observer.stop()
        observer.join()
        sys.exit(0)


def connection_thread(local_socket: socket.socket, service: Service, global_config: dict, watchdog_handler, count):
    """This method is executed in a thread. It will relay data between the local
    host and the remote host, while letting modules work on the data before
    passing it on."""
    remote_socket = socket.socket(get_address_family(service.target_ip))

    try:
        remote_socket.connect((service.target_ip, service.target_port))
        utils.vprint(f'Connected to {remote_socket.getpeername()[0]},{remote_socket.getpeername()[1]}', global_config["verbose"])
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            for s in [remote_socket, local_socket]:
                s.close()
            print(
                f'{time.strftime("%Y%m%d-%H%M%S")}, {service.target_ip}:{service.target_port}- Connection refused')
            return None
        elif serr.errno == errno.ETIMEDOUT:
            for s in [remote_socket, local_socket]:
                s.close()
            print(
                f'{time.strftime("%Y%m%d-%H%M%S")}, {service.target_ip}:{service.target_port}- Connection timed out')
            return None
        else:
            for s in [remote_socket, local_socket]:
                s.close()
            raise serr

    # This loop ends when no more data is received on either the local or the
    # remote socket
    if service.http:
        stream = HTTPStream(global_config["max_stored_messages"], global_config["max_message_size"])
    else:
        stream = TCPStream(global_config["max_stored_messages"], global_config["max_message_size"])

    checker_threshold_us = global_config.get("checker_rtt_threshold_us")

    connection_open = True
    while connection_open:
        ready_sockets, _, _ = select.select(
            [remote_socket, local_socket], [], [])
        if ssl_utils.start_tls(service.ssl, local_socket, ready_sockets):
            try:
                ssl_sockets = ssl_utils.enable_ssl(
                    service.ssl, remote_socket, local_socket)
                remote_socket, local_socket = ssl_sockets
                utils.vprint("SSL enabled", global_config["verbose"])
            except ssl.SSLError as e:
                if e.reason != "SSLV3_ALERT_CERTIFICATE_UNKNOWN":
                    print("SSL handshake failed", str(e))
                break

            ready_sockets, _, _ = select.select(ssl_sockets, [], [])

        for sock in ready_sockets:
            try:
                peer = sock.getpeername()
            except socket.error as serr:
                if serr.errno == errno.ENOTCONN:
                    print(
                        f"{time.strftime('%Y%m%d-%H%M%S')}: Socket error (ENOTCONN) in connection_thread")
                    for s in [remote_socket, local_socket]:
                        s.close()
                    connection_open = False
                    break
                else:
                    print(
                        f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in connection_thread")
                    raise serr

            try:
                stream.set_current_message(utils.receive_from(sock, service.http, global_config["verbose"]))
            except socket.error as serr:
                utils.vprint(
                    f"{time.strftime('%Y%m%d-%H%M%S')}: Socket exception in connection_thread: connection reset by local or remote host")
                remote_socket.close()
                local_socket.close()
                connection_open = False
                break

            utils.vprint('Received %d bytes' %
                         len(stream.current_message), global_config["verbose"])

            if sock == local_socket:
                # going from client to service
                if not len(stream.current_message):
                    utils.vprint(f"Connection from local client {peer[0]},{peer[1]}' closed", global_config["verbose"])
                    remote_socket.close()
                    local_socket.close()
                    connection_open = False
                    break

                if stream.last_response_sent_at is not None:
                    gap_us = int((time.monotonic() - stream.last_response_sent_at) * 1_000_000)
                    prev_min = stream.min_rtt_us
                    prev_label = stream.is_likely_checker
                    stream.record_rtt_sample(gap_us, checker_threshold_us)
                    new_min_hit = prev_min is None or gap_us < prev_min
                    label_changed = prev_label != stream.is_likely_checker
                    if new_min_hit or label_changed:
                        ua = "-"
                        if service.http and getattr(stream, "current_http_message", None) is not None:
                            ua = stream.current_http_message.headers.get("user-agent", "-") or "-"
                        print(
                            f"[rtt] {service.name} {peer[0]} "
                            f"gap={gap_us}us min={stream.min_rtt_us}us "
                            f"samples={len(stream.rtt_samples)} "
                            f"checker={stream.is_likely_checker} ua={ua!r}"
                        )
                    if label_changed:
                        if stream.is_likely_checker is True:
                            reason = f"min {stream.min_rtt_us}us < threshold {checker_threshold_us}us"
                        elif stream.is_likely_checker is False:
                            reason = f"first sample {gap_us}us >= threshold {checker_threshold_us}us"
                        else:
                            reason = "threshold unset"
                        print(
                            f"[rtt-classify] {service.name} {peer[0]} "
                            f"{prev_label}->{stream.is_likely_checker} ({reason})"
                        )

                utils.vprint(b'> > > in\n' + stream.current_message, global_config["verbose"])
                attack = utils.filter_packet(stream, watchdog_handler.in_module)
                if not attack:
                    remote_socket.send(stream.current_message)
            else:
                # going from service to client
                if not len(stream.current_message):
                    utils.vprint(f"Connection from remote server {peer[0]},{peer[1]} closed", global_config["verbose"])
                    remote_socket.close()
                    local_socket.close()
                    connection_open = False
                    break

                utils.vprint(b'< < < out\n' + stream.current_message, global_config["verbose"])
                attack = utils.filter_packet(stream, watchdog_handler.out_module)
                if not attack:
                    local_socket.send(stream.current_message)
                    stream.last_response_sent_at = time.monotonic()

            if attack:
                utils.vprint(f"Connection {peer[0]},{peer[1]} BLOCKED", global_config["verbose"])
                count.value += 1
                block_answer = global_config["keyword"]
                utils.block_packet(local_socket, get_address_family(service.listen_ip), remote_socket, block_answer, global_config.get("dos", None))
                connection_open = False
                break
