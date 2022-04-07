import queue
import struct
from enum import Enum
from random import getrandbits
from time import sleep

from btcp.constants import *
from btcp.lossy_layer import LossyLayer


class BTCPStates(Enum):
    """Enum class that helps you implement the bTCP state machine.

    These states are NOT exhaustive! We left out some states that you will need
    to implement the bTCP state machine correctly. The intention of this enum
    is to give you some idea for states and how simple the transitions between
    them are.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.
    """
    CLOSED = 0
    ACCEPTING = 1
    SYN_SENT = 2
    SYN_RCVD = 3
    ESTABLISHED = 4
    FIN_SENT = 5
    CLOSING = 6
    __ = 7  # If you need more states, extend the Enum like this.


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """

    def __init__(self, window, timeout, user):
        self._window = window
        self._timeout = timeout
        self._user = user
        if user == "client":
            self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
        elif user == "server":
            self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)
        else:
            raise Exception("Invalid type, should be server or client")
        self._flag = False
        self._state = None
        self._SEQ = None
        self._SEQ_first = None
        self._ACK = None
        self._sent_packet = []

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        self._recvbuf = queue.Queue(maxsize=1000)

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        """
        seq, ack, flags, window, datalen, checksum = self.unpack_segment_header(segment[:10])
        if not BTCPSocket.in_cksum(segment, validity=True):
            print("INVALID CHK")

            return
        if self._state == BTCPStates.ACCEPTING:
            if flags == 4:  # SYN rcv
                self._state = BTCPStates.SYN_RCVD
                self._ACK = seq
                return
        if self._state == BTCPStates.SYN_SENT:
            if flags == 6:  # SYN&ACK rcv
                self._flag = False
                self._SEQ = seq + 1
                self._SEQ_first = seq
                self._ACK = ack
                self._window = window
            if flags == 2:  # ACK rcv
                self._ACK = ack
                self._SEQ = seq + 1
                self._state = BTCPStates.ESTABLISHED
                print("SEQ ACK ", self._SEQ, self._ACK)
                return
        if self._state == BTCPStates.FIN_SENT:
            if flags == 3:  # FIN&ACK rcv
                self._flag = False
                self._SEQ = seq
                self._ACK = ack
        if self._state == BTCPStates.ESTABLISHED and not flags == 1:
            if self._user == "client":
                if flags == 2:  # ACK rcv
                    if self._SEQ_first != ack:  # not duplicate
                        self._ACK = ack
                        print("RCV ACK PACKET +", self._ACK)
                        if self._SEQ_first < self._ACK < self._SEQ:
                            while self._SEQ_first <= self._ACK:
                                self._SEQ_first += 1
                                self._window += 1
                                self._sent_packet.pop(0)
                        else:
                            print("RCV DUPLICATE ACK")
            if self._user == "server":
                if seq == self._ACK % 65535:  # sequence number segment is the expected sequence number meaning no loss of packet
                    try:
                        self._recvbuf.put_nowait(segment[10:(10 + datalen)])
                    except queue.Full:
                        self._ACK -= 1  # decrease ack by one to not acknowledge dropped data
                    self._ACK += 1
                    self.respond()
                    print("SEND ACK FOR PACKET + ", self._ACK)

                    self._SEQ += 1
                else:  # not expected segment, drop it and send same old ack again.
                    print("RECEIVED NOT EXPECTED PACKET - DROP ", self._ACK, seq)
                    self.respond()

    def respond(self, ack_flag=True, fin_flag=False, ):
        segment = self.build_segment_header(self._SEQ, self._ACK, fin_set=fin_flag, ack_set=ack_flag, ) + 1008 * b'\x00'
        checksum = BTCPSocket.in_cksum(segment)
        segment = self.build_segment_header(self._SEQ, self._ACK, checksum=checksum, fin_set=fin_flag,
                                            ack_set=ack_flag) + 1008 * b'\x00'

        self._lossy_layer.send_segment(segment)
        return

    @staticmethod
    def in_cksum(segment, validity=False):
        """Compute the internet checksum of the segment given as argument.
        Consult lecture 3 for details.

        Our bTCP implementation always has an even number of bytes in a segment.

        Remember that, when computing the checksum value before *sending* the
        segment, the checksum field in the header should be set to 0x0000, and
        then the resulting checksum should be put in its place.
        """
        if not segment:
            return 0x0000

        # Sum the entire run as 16-bit integers in network byte order.
        acc = sum(x for (x,) in struct.iter_unpack(R'!H', segment))

        # (Repeatedly) carry the overflow around until it fits in 16 bits.
        while acc > 0xFFFF:
            carry = acc >> 16
            acc &= 0xFFFF
            acc += carry

        # Return the binary inverse except when the result is 0xFFFF
        if validity:
            return acc == 0xFFFF
        else:
            return acc if acc == 0xFFFF else (~acc & 0xFFFF)

    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack

        This method is given because historically students had a lot of trouble
        figuring out how to pack and unpack values into / out of the header.
        We have *not* provided an implementation of the corresponding unpack
        method (see below), so inspect the code, look at the documentation for
        struct.pack, and figure out what this does, so you can implement the
        unpack method yourself.

        Of course, you are free to implement it differently, as long as you
        do so correctly *and respect the network byte order*.

        You are allowed to change the SYN, ACK, and FIN flag locations in the
        flags byte, but make sure to do so correctly everywhere you pack and
        unpack them.

        The method is written to have sane defaults for the arguments, so
        you don't have to always set all flags explicitly true/false, or give
        a checksum of 0 when creating the header for checksum computation.
        """
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)

    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.

        Remember that Python supports multiple return values through automatic
        tupling, so it's easy to simply return all of them in one go rather
        than make a separate method for every individual field.
        """
        seqnum, ack, flags, window, datalen, checksum = struct.unpack("!HHBBHH", header)
        return seqnum, ack, flags, window, datalen, checksum

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """

        # Send all data available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        # You should be checking whether there's space in the window as well,
        # and storing the segments for retransmission somewhere.
        while True:
            try:
                # Get a chunk of data from the buffer, if available.
                chunk = self._sendbuf.get_nowait()
                datalen = len(chunk)
                if datalen < PAYLOAD_SIZE:
                    chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
                segment = self.build_segment_header(self._SEQ, 0, length=datalen) + chunk
                checksum = BTCPSocket.in_cksum(segment)
                segment = self.build_segment_header(self._SEQ, 0, checksum=checksum, length=datalen) + chunk
                self._lossy_layer.send_segment(segment)
                self._SEQ += 1
                print("SEND PACKET + ", self._SEQ % 65535, self._ACK)
                self._sent_packet.append(segment)
            except queue.Empty:
                # No data was available for sending.
                break

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        self._SEQ = getrandbits(16)

        syn_segment = self.build_segment_header(self._SEQ, 0, syn_set=True) + 1008 * b'\x00'
        checksum = BTCPSocket.in_cksum(syn_segment)
        syn_segment = self.build_segment_header(self._SEQ, 0, checksum=checksum, syn_set=True) + 1008 * b'\x00'

        self._lossy_layer.send_segment(syn_segment)
        self._state = BTCPStates.SYN_SENT
        self._flag = True
        while self._flag:
            sleep(0.1)  # 100ms
            continue
        ack_segment = BTCPSocket.build_segment_header(self._ACK, self._SEQ, ack_set=True) + 1008 * b'\x00'
        checksum = BTCPSocket.in_cksum(ack_segment)
        ack_segment = BTCPSocket.build_segment_header(self._ACK, self._SEQ, checksum=checksum,
                                                      ack_set=True) + 1008 * b'\x00'

        self._lossy_layer.send_segment(ack_segment)
        self._state = BTCPStates.ESTABLISHED

        return

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection.

        accept should *block* (i.e. not return) until a connection has been
        successfully established (or some timeout is reached, if you want. Feel
        free to add a timeout to the arguments). You will need some
        coordination between the application thread and the network thread for
        this, because the syn and final ack from the client will be received in
        the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        self._state = BTCPStates.ACCEPTING
        while self._state:

            if self._state == BTCPStates.SYN_RCVD:
                break
            continue
        self._SEQ = getrandbits(16)
        syn_ack = self.build_segment_header(self._SEQ, self._ACK, window=self._window, syn_set=True,
                                            ack_set=True, ) + 1008 * b'\x00'
        checksum = BTCPSocket.in_cksum(syn_ack)
        syn_ack = self.build_segment_header(self._SEQ, self._ACK, window=self._window, checksum=checksum, syn_set=True,
                                            ack_set=True) + 1008 * b'\x00'

        self._lossy_layer.send_segment(syn_ack)
        self._state = BTCPStates.SYN_SENT

    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """

        # Example with a finite buffer: a queue with at most 1000 chunks,
        # for a maximum of 985KiB data buffered to get turned into packets.
        # See BTCPSocket__init__() in btcp_socket.py for its construction.

        datalen = len(data)
        sent_bytes = 0
        while sent_bytes < datalen:
            # Loop over data using sent_bytes. Reassignments to data are too
            # expensive when data is large.
            chunk = data[sent_bytes:sent_bytes + PAYLOAD_SIZE]
            try:
                self._sendbuf.put_nowait(chunk)
                self._window -= 1
                while True:
                    if self._window == 0:
                        continue
                    else:
                        break

                sent_bytes += len(chunk)
            except queue.Full:
                break
        return sent_bytes

    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way.

        If no data is available to return to the application, this method
        should block waiting for more data to arrive. If the connection has
        been terminated, this method should return with no data (e.g. an empty
        bytes b'').

        If you want, you can add an argument to this method stating how many
        bytes you want to receive in one go at the most (but this is not
        required for this project).

        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "recv" operates on a "receive
        buffer". Once data has been successfully received and acknowledged by
        the transport layer, it is put "in the receive buffer". A call to recv
        will simply return data already in the receive buffer to the
        application.  If no data is available at all, the method will block
        until at least *some* data can be returned.
        The actual receiving of the data, i.e. reading the segments, sending
        acknowledgements for them, reordering them, etc., happens *outside* of
        the recv method (e.g. in the network thread).
        Because of this blocking behaviour, an *empty* result from recv signals
        that the connection has been terminated.

        Again, you should feel free to deviate from how this usually works.
        """

        # Rudimentary example implementation:
        # Empty the queue in a loop, reading into a larger bytearray object.
        # Once empty, return the data as bytes.
        # If no data is received for 10 seconds, this returns no data and thus
        # signals disconnection to the server application.
        # Proper handling should use the bTCP state machine to check that the
        # client has disconnected when a timeout happens, and keep blocking
        # until data has actually been received if it's still connected.
        data = bytearray()
        try:
            # Wait until one segment becomes available in the buffer, or
            # timeout signalling disconnect.

            data.extend(self._recvbuf.get(block=True, timeout=10))
            while True:
                # Empty the rest of the buffer, until queue.Empty exception
                # exits the loop. If that happens, data contains received
                # segments so that will *not* signal disconnect.
                data.extend(self._recvbuf.get_nowait())
        except queue.Empty:
            pass  # (Not break: the exception itself has exited the loop)
        if self._state == BTCPStates.CLOSED:
            self.close()
            return
        return bytes(data)

    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        fin_segment = self.build_segment_header(self._SEQ, self._ACK, fin_set=True)
        self._lossy_layer.send_segment(fin_segment)
        self._state = BTCPStates.FIN_SENT
        self._flag = True
        while self._flag:
            sleep(0.1)  # 100ms
            continue
        ack_segment = BTCPSocket.build_segment_header(self._ACK, self._SEQ, ack_set=True)
        self._lossy_layer.send_segment(ack_segment)
        self._state = BTCPStates.CLOSED
        return

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """

        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        self.close()
