import queue
import struct
import sys
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
        self._retries = 0
        self._ack_drop = 0
        self._packet_drop = 0

        self._packet_sent = {}
        self._packet_timestamps = []

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=8192)
        self._recvbuf = queue.Queue(maxsize=8192)

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
        if not BTCPSocket.in_cksum(segment, validity=True):
            # Perform checksum validation. If it is invalid drop the packet
            # If it is received on the server side send an ACK with the previous correctly received packet
            if flags == 0 or (flags == 1 and self._state != BTCPStates.FIN_SENT):
                self.respond()
                return
            elif flags == 2:
                return

        if self._state == BTCPStates.ACCEPTING:
            if flags == 4:  # SYN rcv
                self._state = BTCPStates.SYN_RCVD
                self._ACK = seq
                return
        if self._state == BTCPStates.SYN_SENT:
            if flags == 6:  # SYN&ACK rcv
                try:
                    # Try-except is due to packet duplication
                    self._packet_sent.pop(self._SEQ)
                    self._packet_timestamps.pop(0)
                except IndexError:
                    pass
                except KeyError:
                    pass
                self._flag = False  # Signal to the client SYN&ACK was rcv
                self._ACK = seq
                self._window = window
                self._window_control = window*3
                return
            if flags == 2:  # ACK rcv
                self._expected_seq = (seq + 1) % MAX_VALUE
                self._ACK = self._expected_seq
                self._state = BTCPStates.ESTABLISHED
                return

        if self._state == BTCPStates.ESTABLISHED and flags == 2 and self._user == BTCPStates.CLIENT:
            if ack == self._last_ACK:
                # Drop duplicate ACK. The first 3 ACK will trigger timeout. Every 3rd ACK will trigger the lossy
                # layer, which will trigger check_timeout()
                self._ack_drop += 1
                if self._ack_drop == 3:
                    self.timeout()
                    return
                if self._ack_drop % 3 == 0:
                    self.lossy_layer_tick()
                    return
                return
            loops = ack - self._last_ACK  # Allows cumulative ACK when the ACK > Last ACK
            if loops < 0:
                loops += MAX_VALUE

            if loops > self._window * 3:
                return
            self._ack_drop = 0
            while loops > 0:
                # pop the segment in the dictionary corresponding to the last ACK
                # pop the timer
                self._last_ACK = (self._last_ACK + 1) % MAX_VALUE
                self._window_control += 1
                loops -= 1
                self._packet_sent.pop(self._last_ACK % MAX_VALUE)
                try:
                    self._packet_timestamps.pop(0)
                except IndexError:
                    pass
            self._last_ACK %= MAX_VALUE
            return

        if self._state == BTCPStates.ESTABLISHED and flags == 0:
            if seq == self._expected_seq:
                try:
                    self._recvbuf.put_nowait(segment[10:(10 + datalen)])
                except queue.Full:
                    self._expected_seq = (self._expected_seq - 1) % MAX_VALUE

                self._ACK = self._expected_seq
                self._expected_seq = (self._expected_seq + 1) % MAX_VALUE
                print("SEND ack {}".format(self._ACK),file=sys.stderr)
                self._packet_drop = 0
                self.respond()
                return

            else:  # not expected segment, drop it and send same old ack again.
                self._packet_drop += 1
                if self._packet_drop % 3 == 0:
                    # Send ACK every 3rd drop in order to reduce overhead
                    self.respond()
                return
        if flags == 1:  # FIN rcv
            self.respond(fin_flag=True)
            return
        if self._state == BTCPStates.FIN_SENT:
            if flags == 3:  # FIN&ACK rcv
                try:
                    # Try-except due to pack duplication
                    self._packet_sent.pop(self._SEQ%MAX_VALUE)
                    self._packet_timestamps.pop(0)
                except IndexError:
                    pass
                self._flag = False
                self._SEQ = seq
                self._ACK = ack
                return
        if self._state == BTCPStates.CLOSED:
            if flags == 2:  # ACK rcv
                self._state = BTCPStates.CLOSED
                return

    def respond(self, ack_flag=True, fin_flag=False, ):
        """
        Used by the server to send ACK packets and FIN&ACK packet
        """
        segment = self.make_packet(0, self._ACK, NO_DATA, self._window, fin_flag=fin_flag,
                                   ack_flag=ack_flag)
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
        """
        Used by the client to send packets, check for timeouts and control the sending window
        """
        if self._user == BTCPStates.SERVER:
            return
        while True:

            if len(self._packet_timestamps) != 0:
                self.check_timeout()

            try:
                if self._window_control <= 0:
                    break
                chunk = self._sendbuf.get_nowait()
                datalen = len(chunk)
                if datalen < PAYLOAD_SIZE:
                    chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
                self._SEQ = (self._SEQ + 1) % MAX_VALUE
                segment = self.make_packet(self._SEQ % MAX_VALUE, 0, chunk, self._window,
                                           length=datalen)
                self._packet_timestamps.append(time.time())
                self._lossy_layer.send_segment(segment)
                self._packet_sent[self._SEQ % MAX_VALUE] = segment
                self._window_control -= 1

            except queue.Empty:
                # No data was available for sending.
                break

    def check_timeout(self):
        timeout = self.get_timeout()  # check for timeout
        if timeout and len(self._packet_sent) != 0:  # timeout
            self.timeout()
            return True
        return False

    def timeout(self):
        """
        Resend all the segments stored in the dictionary and append new timers, pop old ones
        """
        sent_packet = self._packet_sent.values()
        for i in sent_packet:
            try:
                self._lossy_layer.send_segment(i)
                self._packet_timestamps.append(time.time())
                self._packet_timestamps.pop(0)
            except IndexError:
                return

    def get_timeout(self):
        current_time = time.time()
        try:
            if current_time - self._packet_timestamps[0] >= 1:
                return True
            else:
                return False
        except IndexError:
            pass

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.
        """
        self._SEQ = getrandbits(16)
        syn_segment = self.make_packet(self._SEQ, 0, NO_DATA, self._window, syn_flag=True)
        self._lossy_layer.send_segment(syn_segment)
        self._packet_sent[self._SEQ] = syn_segment
        self._packet_timestamps.append(time.time())
        self._state = BTCPStates.SYN_SENT
        self._flag = True
        while self._flag:  # Wait to rcv SYN&ACK
            if self.check_timeout():
                self._retries += 1
            if self._retries == MAX_RETRIES:
                self._state = BTCPStates.CLOSED
                self.shutdown()
                self.close()
                return
            time.sleep(0.1)  # 100ms

        ack_segment = self.make_packet(self._SEQ, self._ACK, NO_DATA, self._window, ack_flag=True)
        self._lossy_layer.send_segment(ack_segment)
        self._last_ACK = self._SEQ % MAX_VALUE
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

            data.extend(self._recvbuf.get(block=True, timeout=5))
            while True:
                # Empty the rest of the buffer, until queue.Empty exception
                # exits the loop. If that happens, data contains received
                # segments so that will *not* signal disconnect.
                data.extend(self._recvbuf.get_nowait())
        except queue.Empty:
            pass  # (Not break: the exception itself has exited the loop)
        if self._state == BTCPStates.CLOSED:
            return
        return bytes(data)

    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.
        """

        while not self._sendbuf.empty() or len(self._packet_sent) != 0:
            sleep(0.1)
            continue
        fin_segment = self.make_packet(self._SEQ % MAX_VALUE, 0, NO_DATA, self._window, fin_flag=True)
        self._state = BTCPStates.FIN_SENT

        self._lossy_layer.send_segment(fin_segment)
        self._packet_sent[self._SEQ % MAX_VALUE] = fin_segment
        self._packet_timestamps.append(time.time())
        self._flag = True
        print("Closing")

        while self._flag:  # Wait for FIN&ACK
            if self.check_timeout():
                self._retries += 1
            if self._retries == MAX_RETRIES:
                self._state = BTCPStates.CLOSED
                self.close()
                return

        self._state = BTCPStates.CLOSED

        ack_segment = self.make_packet(self._SEQ % MAX_VALUE, self._ACK, NO_DATA, self._window, ack_flag=True)
        self._lossy_layer.send_segment(ack_segment)
        print("ACK SENT")
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
