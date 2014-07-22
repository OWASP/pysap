## ===========
## pysap - Python library for crafting SAP's network protocols packets
##
## Copyright (C) 2014 Core Security Technologies
##
## The library was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============

# Standard imports
import logging
from struct import unpack
from SocketServer import ThreadingTCPServer, BaseRequestHandler
# External imports
#from scapy.all import *
from scapy.fields import LenField
from scapy.packet import Packet, Raw
from scapy.supersocket import socket, StreamSocket
# Custom imports
from pysap.utils import Worker


# Create a logger for the SAPNI layer
log_sapni = logging.getLogger("pysap.sapni")


class SAPNI(Packet):
    """
    SAP NI (Network Interface) packet

    This packet is used for craft Network Interface packets. It serves only
    as a container for packets in the different protocols. As this protocol
    is used by different protocols and the only way to differentiate each one
    is by the TCP port used, each script using the NI protocol must bind the
    respective layer with the respective protocol.

    For example, a script using the SAP Diag protocol must include the
    following binds::

        bind_layers(SAPNI,      SAPDiag, )
        bind_layers(SAPNI,      SAPDiagDP, )
        bind_layers(SAPDiagDP,  SAPDiag, )
        bind_layers(SAPDiag,    SAPDiagItem, )
        bind_layers(SAPDiagItem,SAPDiagItem, )

    """
    name = "SAP NI (Network Interface) protocol"
    fields_desc = [LenField("length", None, fmt="!I")]

    # Constants for keep-alive messages
    SAPNI_PING = "NI_PING\x00"
    """ @cvar: Constant for keep-alive request messages (NI_PING)
        @type: C{string} """

    SAPNI_PONG = "NI_PONG\x00"
    """ @cvar: Constant for keep-alive response messages (NI_PONG)
        @type: C{string} """


class SAPNIStreamSocket(StreamSocket):
    """
    Stream socket implementation of the Network Interface layer.

    """

    desc = "NI Stream socket"

    def __init__(self, sock, keep_alive=True):
        """
        Initializes the NI stream socket.

        @param sock: socket
        @type sock: C{socket}

        @param keep_alive: if true, the socket will automatically respond to
            keep-alive request messages. Otherwise, the keep-alive messages
            are passed to the caller in L{recv} and L{sr} calls.
        @type keep_alive: C{bool}
        """
        StreamSocket.__init__(self, sock, Raw)
        self.keep_alive = keep_alive

    def send(self, packet):
        """
        Send a packet at the NI layer, prepending the length field.

        @param packet: packet to send
        @type packet: Packet
        """
        # Add the NI layer and send
        log_sapni.debug("To send %d bytes", len(packet) + 4)
        return StreamSocket.send(self, SAPNI() / packet)

    def recv(self):
        """
        Receive a packet at the NI layer, first reading the length field and
        the reading the data. If the stream is waiting for a new packet and
        the remote peer sends a keep-alive request (L{NI_PING<SAPNI.SAPNI_PING>}), the receive
        method will respond with a keep-alive response (L{NI_PONG<SAPNI.SAPNI_PONG>}) to keep the
        communication stable.

        @return: received L{SAPNI} packet
        @rtype: L{SAPNI}

        @raise socket.error: if the connection was close
        """
        # Receive the NI length field
        nidata = self.ins.recv(4, socket.MSG_PEEK)
        if len(nidata) == 0:
            raise socket.error((100, "Underlying stream socket tore down"))
        (nilength, ) = unpack("!I", nidata)
        log_sapni.debug("To receive %d bytes", nilength)

        # Receive the whole NI packet (length+payload)
        nidata = ''
        while(len(nidata) < nilength + 4):
            nidata += self.ins.recv(nilength - len(nidata) + 4)
            if (len(nidata) == 0):
                raise socket.error((100, "Underlying stream socket tore down"))

        # If the packet received is a keep-alive request (NI_PING), send a
        # response (NI_PONG) and make a new receive call
        if nilength == len(SAPNI.SAPNI_PING) and nidata[4:] == SAPNI.SAPNI_PING:
            log_sapni.debug("Received NI_PING")
            if self.keep_alive:
                log_sapni.debug("Keep alive set, sending NI_PONG")
                self.send(Raw(SAPNI.SAPNI_PONG))
                return self.recv()

        # Build the SAPNI packet with the received data
        log_sapni.debug("Received %d bytes", nilength)
        return SAPNI(nidata)

    def sr(self, packet):
        """
        Send a given packet and receive the response. Wrapper around the send
        and receive methods. The response packet is build in the L{SAPNI} layer.

        @param packet: packet to send
        @type packet: Packet

        @return: packet received
        @rtype: Packet
        """
        self.send(packet)
        return self.recv()

    @classmethod
    def get_nisocket(cls, host, port, **kwargs):
        """
        Helper function to obtain a L{SAPNIStreamSocket}.

        @param host: host to connect to
        @type host: C{string}

        @param port: port to connect to
        @type port: C{int}

        @keyword kwargs: arguments to pass to L{SAPNIStreamSocket} constructor

        @return: connected socket
        @rtype: L{SAPNIStreamSocket}
        """
        sock = socket.socket()
        sock.connect((host, port))
        return cls(sock, **kwargs)


class SAPNIProxy(object):
    """
    SAP NI Proxy

    It works by setting a listener L{SAPNIStreamSocket} and dispatching client's
    requests to a given handler class.

    Example usage::
        proxy = SAPNIProxy(local_host, local_port, remote_host, remote_port, handler_class)
        proxy.handle_connection()
    """

    def __init__(self, bind_address, bind_port, remote_address, remote_port,
                 handler, backlog=5, keep_alive=True, options=None):
        """
        Create the proxy binding a socket in the giving port and setting the
        handler for the incoming connections.

        @param bind_address: address to bind the listener socket
        @type bind_address: C{string}

        @param bind_port: port to bind the listener socket
        @type bind_port: C{int}

        @param remote_address: remote address to connect to
        @param remote_address: C{string}

        @param remote_port: remote port to connect to
        @type remote_port: C{int}

        @param handler: handler class
        @type handler: L{SAPNIProxyHandler} class

        @param backlog: backlog parameter to set in the listener socket
        @type backlog: C{int}

        @param keep_alive:  if true, the proxy will handle the keep-alive
            requests and responses. Otherwise, keep-alive messages are passed
            to the handler as regular packets.
        @type keep_alive: C{bool}

        @param options: options to pass to the handler instance
        @type options: C{dict}
        """
        self.remote_host = (remote_address, remote_port)
        self.handler = handler
        self.keep_alive = keep_alive
        self.options = options

        # Create and bind the listener socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, bind_port))
        sock.listen(backlog)

        # Create the NI Stream Socket
        self.listener = SAPNIStreamSocket(sock, keep_alive)

        log_sapni.debug("SAPNIProxy: Binded to address %s:%d, proxying to %s:%d",
                        bind_address, bind_port, remote_address, remote_port)

    def handle_connection(self):
        """
        Block until a connection is received from the listener and handle that
        client using the provided handler class.

        @return: the handler instance handling the request
        @rtype: L{SAPNIProxyHandler}
        """
        # Accept a client connection
        (client, address) = self.listener.ins.accept()

        # Creates a remote socket
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(self.remote_host)

        # Create the NI Stream Socket and handle it
        proxy = self.handler(SAPNIStreamSocket(client, self.keep_alive),
                             SAPNIStreamSocket(remote, self.keep_alive),
                             self.options)

        log_sapni.debug("SAPNIProxy: Handled a connection from %s", address)
        return proxy


class SAPNIProxyHandler(object):
    """
    SAP NI Proxy Handler

    Handles NI packets. Works spawning one thread for processing data coming
    from the client and another one for data coming from the server.
    """

    def __init__(self, client, server, options=None):
        """
        It receives two L{SAPNIStreamSocket}s objects and creates the upload and
        download workers for processing data. Threads are started as daemons.

        @param client: client Stream Socket
        @type client: L{SAPNIStreamSocket}

        @param server: server Stream Socket
        @type server: L{SAPNIStreamSocket}

        @param options: options received from the proxy
        @type options: C{dict}
        """
        self.client = client
        self.server = server

        upload_processor = Worker(self, self._upload)
        download_processor = Worker(self, self._download)
        upload_processor.daemon = True
        download_processor.daemon = True
        upload_processor.start()
        download_processor.start()

    def recv_send(self, local, remote, process):
        """
        Receives data from one socket connection, process it and send to the
        remote connection.

        @param local: the local socket
        @type local: L{SAPNIStreamSocket}

        @param remote: the remote socket
        @type remote: L{SAPNIStreamSocket}

        @param process: the function that process the incoming data
        @type process: function
        """
        # Receive a SAP NI packet
        packet = local.recv()
        log_sapni.debug("SAPNIProxyHandler: Received %d bytes", len(packet))
        # Process the packet using the given function
        packet = process(packet)
        # Send the packet to the remote peer
        remote.send(packet.payload)
        log_sapni.debug("SAPNIProxyHandler: Sent %d bytes", len(packet))

    def _upload(self):
        """
        Handles data coming from the upload stream (client to server)
        """
        log_sapni.debug("SAPNIProxyHandler: Client to Server connection")
        self.recv_send(self.client, self.server, self.process_client)

    def _download(self):
        """
        Handles data coming from the download stream (server to client)
        """
        log_sapni.debug("SAPNIProxyHandler: Server to Client connection")
        self.recv_send(self.server, self.client, self.process_server)

    def process_client(self, packet):
        """
        This method is called each time a packet arrives from the client.
        It must return a packet in the same layer (SAP NI). Stub method
        to be overloaded in subclasses.

        @param packet: the packet to be processed
        @type packet: Packet
        """
        return packet

    def process_server(self, packet):
        """
        This method is called each time a packet arrives from the server.
        It must return a packet in the same layer (SAP NI). Stub method
        to be overloaded in subclasses.

        @param packet: the packet to be processed
        @type packet: Packet
        """
        return packet


class SAPNIClient(object):
    """
    Stub class for a client connecting to the SAP NI server.
    """
    pass


class SAPNIServerThreaded(ThreadingTCPServer):
    """
    Base SAP NI Threaded Server class.

    Subclasses must define a client class for keeping state information
    on the connected clients.

    Example usage::
        server = SAPNIServerThreaded((local_host, local_port), handler_class)
        server.client_cls = client_class
        server.serve_forever()
    """
    # XXX: Implement a socket server using a NIStreamSocket
    clients_cls = SAPNIClient
    """ @cvar: Client class for storing data about new clients
        @type: L{SAPNIClient} class """

    clients = {}
    """ @ivar: Clients connected to the server
        @type: L{clients_cls} """

    options = None
    """ @ivar: Options to pass to the request handler
        @type: C{object} """


class SAPNIServerHandler(BaseRequestHandler):
    """
    SAP NI Server Handler

    Handles L{SAPNI} packets coming from a SocketServer.
    """

    def setup(self):
        """
        Setup a new client connection. Creates a new client object for keeping
        state information of each client on the server instance.
        """
        if self.client_address not in self.server.clients.keys():
            self.server.clients[self.client_address] = self.server.clients_cls()
            log_sapni.debug("SAPNIServerHandler: New client %s",
                            self.client_address)

    def close(self):
        """
        Close a client connection and deletes the client from the state
        information on the server.

        """
        del(self.server.clients[self.client_address])
        log_sapni.debug("SAPNIServerHandler: Bye client %s", self.client_address)
        self.request.close()

    def handle(self):
        """
        Handle a client connection. After received a L{SAPNI} packet, it stores it
        on the packet instance variable and pass the control to the handle_data
        method.

        """
        while True:
            log_sapni.debug("SAPNIServerHandler: Handling data from %s",
                            self.client_address)
            nidata = self.request.recv(4)
            if (len(nidata) == 0):
                self.close()
                continue

            while (len(nidata) < 4):
                nidata += self.request.recv(4 - len(nidata))

            (nilength, ) = unpack("!I", nidata)

            log_sapni.debug("SAPNIServerHandler: To receive %d bytes from %s",
                            nilength, self.client_address)

            self.data = ''
            while(len(self.data) < nilength):
                self.data += self.request.recv(nilength - len(self.data))
                if (len(self.data) == 0):
                    self.close()
                    continue

            # Store the packet
            self.packet = SAPNI(nidata + self.data)

            log_sapni.debug("SAPNIServerHandler: Request received")
            # Pass the control to the handle_data function
            self.handle_data()

    def handle_data(self):
        """
        Handle the data coming from the client. The L{SAPNI} packet is stored on
        data and client information on client_address instance variables.
        Stub method to be overloaded in subclasses.

        """
        pass
