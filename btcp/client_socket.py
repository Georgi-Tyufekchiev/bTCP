from time import sleep

from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from random import getrandbits
import queue
import time


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use Queues, or a similar thread safe collection.
    """

    def __init__(self, window, timeout):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call connect from here.
        """
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
        self._flag = False
        self._s_window = None
        self._state = None
        self._SEQ = None
        self._SEQ_first = None
        self._ACK = None
        self._sent_packet = []
        self._packet_timestamps = []
        self.count = 0

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)

        self._window_size = 100
        self._window_start = None
        self._window_end = None

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
        if self._state == BTCPStates.SYN_SENT:
            if flags == 6:  # SYN&ACK rcv
                self._flag = False
                self._SEQ = seq + 1
                self._SEQ_first = seq
                self._ACK = ack
                self._s_window = window
        if self._state == BTCPStates.FIN_SENT:
            if flags == 3:  # FIN&ACK rcv
                self._flag = False
                self._SEQ = seq
                self._ACK = ack
        if self._state == BTCPStates.ESTABLISHED:
            if flags == 2 and self._SEQ_first != self._ACK:  # ACK rcv and not duplicate
                self._ACK = ack
                print("RCV ACK PACKET +", self._ACK)
                if self._SEQ_first < self._ACK < self._SEQ:
                    while self._SEQ_first <= self._ACK:
                        self._SEQ_first += 1
                        self._sent_packet.pop(0)
                        self._packet_timestamps.pop(0)

            else:
                print("RCV DUPLICATE ACK")

        if self._state == BTCPStates.ESTABLISHED:
            pass
            # acknowledge that every sequence number <= to ack - 1 has been received.
            # move window
            # resend where necessary

        try:
            pass
        except queue.Full:
            # Data gets silently dropped if the receive buffer is full. You
            # need to ensure this doesn't happen by using window sizes and not
            # acknowledging dropped data.
            pass

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
                print("SEND PACKET + ", self._SEQ % 65535, self._ACK, self.count)
                self.count += 1
                self._sent_packet.append(segment)
            except queue.Empty:
                # No data was available for sending.
                break

        timeout = self.timeout_check()  #check for timeout
        if timeout[0] == -1:            #no timeout
            return
        
        for i in range(timeout[0], timeout[1] + 1):     #for every timeout first resend, then append new timestamp, then append packet to sent_packet, then remove first entry in both
            self._lossy_layer.send_segment(self._sent_packet[0])
            self._packet_timestamps.append(time.time())
            self._sent_packet.append(self._sent_packet[0])
            self._sent_packet.pop(0)
            self._packet_timestamps.pop(0)


    #checks whether packets have timed out, if so it returns a tuple (0, upperbound) which are indices in self._sent_packet
    #if not packet timed out (-1,-1) is returned
    def timeout_check(self):
        i = 0
        lower_bound = -1
        upper_bound = -1
        current_time = time.time()  
        while i < len(self._packet_timestamps) and current_time - self._packet_timestamps[i] >= 1:   #timeout after 1 sec
            lower_bound = 0
            upper_bound = i
            i += 1
            current_time = time.time()
        print("bounds: \t"+  str(lower_bound) + "\t" + str(upper_bound))
        return (lower_bound, upper_bound)

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
                while True:
                    if self._sendbuf.qsize() >= self._s_window:
                        continue
                    else:
                        break
                sent_bytes += len(chunk)
            except queue.Full:
                break
        return sent_bytes

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
