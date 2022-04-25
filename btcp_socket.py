import queue
import struct
import time
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
    ESTABLISHING = 9
    FIN_SENT = 5
    CLOSING = 6
    SERVER = 7
    CLIENT = 8


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """

    def __init__(self, window, timeout):
        self._user = None
        self._lossy_layer = None
        self._window = window
        self._window_control = 0
        self._timeout = timeout
        self._flag = False
        self._state = None
        self._SEQ = 0
        self._expected_seq = 0
        self._last_ACK = 0
        self._ACK = 0
        self._count_drop = 0
        self._count = 0
        self._count2 = 0

        self._packet_timestamps = []
        self._sent_packet = []

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        self._recvbuf = queue.Queue(maxsize=1000)

    def bind(self, localIP, localPort, remoteIP, remotePort):
        """
        Bind the socket to the proper IPs and Ports
        """
        self._lossy_layer = LossyLayer(self, localIP, localPort, remoteIP, remotePort)
        if localPort == SERVER_PORT:
            self._user = BTCPStates.SERVER
        else:
            self._user = BTCPStates.CLIENT

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.
        """
        seq, ack, flags, window, datalen, checksum = self.unpack_segment_header(segment[:10])
        if not BTCPSocket.in_cksum(segment, validity=True) and flags == 0:
            print("CORRUPT FROM CLIENT", seq)
            self._ACK = (self._expected_seq - 1) % self._window

            self.respond()
            return
        if not BTCPSocket.in_cksum(segment, validity=True) and flags == 2:
            print("CORRUPT FROM SERVER", ack)
            return

        if self._state == BTCPStates.ACCEPTING:
            if flags == 4:  # SYN rcv
                self._state = BTCPStates.SYN_RCVD
                self._ACK = seq
                return
        if self._state == BTCPStates.SYN_SENT:
            if flags == 6:  # SYN&ACK rcv
                print("SYN&ACK!!!!!!!")
                try:
                    self._sent_packet.pop(0)
                    self._packet_timestamps.pop(0)
                except IndexError:
                    pass
                self._flag = False
                self._ACK = seq
                self._window = window
                self._window_control = window
                return
            if flags == 2:  # ACK rcv
                self._expected_seq = (seq + 1) % self._window
                self._ACK = self._expected_seq
                self._state = BTCPStates.ESTABLISHED
                return

        if self._state == BTCPStates.ESTABLISHED and flags == 2:
            if ack == self._last_ACK:
                # if self._count_drop == 3 and len(self._sent_packet) != 0:
                print("DROP ACK", ack)
                self._count_drop += 1
                return

            if self._last_ACK > ack:  # 99 - 105
                ack += self._window
                print("HIT SPECIAL CASE ack lack", ack, self._last_ACK)
            # 0 < 14
            while self._last_ACK < ack:
                print("RCV ack {} count {} and lack {}".format(ack, seq, self._last_ACK))

                self._window_control += 1
                self._sent_packet.pop(0)
                self._packet_timestamps.pop(0)
                self._last_ACK = self._last_ACK + 1
            self._last_ACK %= self._window
            return

        if self._state == BTCPStates.ESTABLISHED and flags == 0:
            if seq == self._expected_seq:
                try:
                    self._recvbuf.put_nowait(segment[10:(10 + datalen)])
                except queue.Full:
                    self._expected_seq = (self._expected_seq - 1) % self._window

                self._ACK = self._expected_seq
                self._expected_seq = (self._expected_seq + 1) % self._window
                print("SEND ack {} and count {}  ".format(self._ACK, self._count2))

                self.respond()
                return

            else:  # not expected segment, drop it and send same old ack again.
                print("DROP count {} seq {} expseq {}".format(ack, seq, self._expected_seq))
                self.respond()
                return
        if flags == 1:  # FIN rcv
            self._state = BTCPStates.CLOSING
            print("FIN RCV ############################")
            self.respond(fin_flag=True)
            return
        if self._state == BTCPStates.FIN_SENT:
            if flags == 3:  # FIN&ACK rcv
                print("FIN ACK RCV !!!!!!!!!!!!!!!!!!!!!!!!")
                try:
                    self._sent_packet.pop(0)
                    self._packet_timestamps.pop(0)
                except IndexError:
                    pass
                self._flag = False
                self._SEQ = seq
                self._ACK = ack
                return
        if self._state == BTCPStates.CLOSING:
            if flags == 2:  # ACK rcv
                print("ACK RCV @@@@@@@@@@@@@@@@@@@@@@")
                self._state = BTCPStates.CLOSED
                return

    def respond(self, ack_flag=True, fin_flag=False, ):
        segment = self.make_packet(self._count2 % 65535, self._ACK, NO_DATA, self._window, fin_flag=fin_flag,
                                   ack_flag=ack_flag)
        self._count2 += 1
        self._lossy_layer.send_segment(segment)
        return

    @staticmethod
    def in_cksum(segment, validity=False):
        """Compute the internet checksum of the segment given as argument or check the validity of the arrived segment.
        The code is taken from the correct version of the packet_sniffer.py provided to us.
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
        """
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)

    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.
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
        if self._user == BTCPStates.SERVER:
            return
        while True:
            if self._count_drop >= 3:
                self._count_drop = 0
                self.timeout((0, len(self._sent_packet)))

            if len(self._packet_timestamps) != 0:
                self.check_timeout()

            try:
                # Get a chunk of data from the buffer, if available.
                if self._window_control <= 0:
                    print("BLOCK")
                    break
                chunk = self._sendbuf.get_nowait()
                datalen = len(chunk)
                if datalen < PAYLOAD_SIZE:
                    chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
                self._SEQ += 1
                segment = self.make_packet(self._SEQ % self._window, self._count % 65535, chunk, self._window,
                                           length=datalen)
                self._count += 1
                self._packet_timestamps.append(time.time())
                self._lossy_layer.send_segment(segment)
                self._sent_packet.append(segment)
                print("PACKET seq {} & count {} ".format(self._SEQ % self._window, self._count))

                self._window_control -= 1

            except queue.Empty:
                # No data was available for sending.
                break
            self.check_timeout()

    def check_timeout(self):
        timeout = self.get_timeout()  # check for timeout
        if timeout[0] != -1:  # timeout
            print("TIMEOUT")
            self.timeout(timeout)

    def timeout(self, timeout: tuple):
        """
         # for every timeout first resend, then append new timestamp, then append packet to sent_packet,
         then remove first entry in both
        """
        print("TIMEOUT PACKS FROM {} TO {}:".format(timeout[0], timeout[1]))

        for i in range(timeout[0], timeout[1] + 1):
            self._lossy_layer.send_segment(self._sent_packet[0])
            self._packet_timestamps.append(time.time())
            self._sent_packet.append(self._sent_packet[0])
            self._sent_packet.pop(0)
            self._packet_timestamps.pop(0)

    def get_timeout(self):
        i = 0
        lower_bound = -1
        upper_bound = -1
        current_time = time.time()
        while i < len(self._packet_timestamps) and current_time - self._packet_timestamps[
            i] >= 1:  # timeout after 1 sec
            lower_bound = 0
            upper_bound = i
            i += 1
            current_time = time.time()
        # print("bounds: \t" + str(lower_bound) + "\t" + str(upper_bound))
        return (lower_bound, upper_bound)

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.
        """
        self._SEQ = getrandbits(16)

        syn_segment = self.make_packet(self._SEQ, 0, NO_DATA, self._window, syn_flag=True)
        self._lossy_layer.send_segment(syn_segment)
        self._sent_packet.append(syn_segment)
        self._packet_timestamps.append(time.time())
        self._state = BTCPStates.SYN_SENT
        self._flag = True
        while self._flag:  # Wait to rcv SYN&ACK
            self.check_timeout()
            sleep(0.1)  # 100ms
            continue

        ack_segment = self.make_packet(self._SEQ, self._ACK, NO_DATA, self._window, ack_flag=True)
        self._lossy_layer.send_segment(ack_segment)
        self._last_ACK = (self._SEQ) % self._window
        self._state = BTCPStates.ESTABLISHED
        return

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection.
        """
        self._state = BTCPStates.ACCEPTING
        while self._state:  # Wait for client
            if self._state == BTCPStates.SYN_RCVD:
                break
            continue
        self._SEQ = getrandbits(16)
        syn_ack = self.make_packet(self._SEQ, self._ACK, NO_DATA, self._window, syn_flag=True, ack_flag=True)
        self._lossy_layer.send_segment(syn_ack)
        self._state = BTCPStates.SYN_SENT

    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.
        """
        datalen = len(data)
        sent_bytes = 0
        while sent_bytes < datalen:
            # Loop over data using sent_bytes. Reassignments to data are too
            # expensive when data is large.
            chunk = data[sent_bytes:sent_bytes + PAYLOAD_SIZE]
            try:
                self._sendbuf.put_nowait(chunk)
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
        """
        data = bytearray()
        try:
            # Wait until one segment becomes available in the buffer, or
            # timeout signalling disconnect.

            data.extend(self._recvbuf.get(block=True, timeout=3))
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
        """
        while not self._sendbuf.empty() and len(self._sent_packet) != 0:
            sleep(0.1)
            continue
        fin_segment = self.make_packet(self._SEQ % self._window, 0, NO_DATA, self._window, fin_flag=True)
        self._lossy_layer.send_segment(fin_segment)
        self._sent_packet.append(fin_segment)
        self._packet_timestamps.append(time.time())
        self._state = BTCPStates.FIN_SENT
        self._flag = True
        while self._flag:  # Wait for FIN&ACK
            print("Closing")
            self.check_timeout()
            sleep(0.1)  # 100ms
            continue

        ack_segment = self.make_packet(self._SEQ % self._window, self._ACK, NO_DATA, self._window, ack_flag=True)
        self._lossy_layer.send_segment(ack_segment)
        self._state = BTCPStates.CLOSED
        return

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.
        """

        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        self.close()

    def make_packet(self, SEQ: int, ACK: int, data: bytes, window: int, ack_flag=False, syn_flag=False, fin_flag=False,
                    length=0):
        """
        Create a packet with its checksum
        """
        packet = BTCPSocket.build_segment_header(SEQ, ACK, window=window, ack_set=ack_flag, syn_set=syn_flag,
                                                 fin_set=fin_flag, length=length) + data
        checksum = BTCPSocket.in_cksum(packet)
        packet = BTCPSocket.build_segment_header(SEQ, ACK, window=window, checksum=checksum, ack_set=ack_flag,
                                                 syn_set=syn_flag,
                                                 fin_set=fin_flag, length=length) + data
        return packet
