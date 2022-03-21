from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *
from random import getrandbits
from time import sleep
import queue


class BTCPServerSocket(BTCPSocket):
    """bTCP server socket
    A server application makes use of the services provided by bTCP by calling
    accept, recv, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API. Do note, however, that this socket
    as presented is *always* in "listening" state, and handles the client's
    connection in the same socket. You do not have to implement a separate
    listen socket. If you get everything working, you may do so for some extra
    credit.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPServerSocket.lossy_layer_segment_received, lossy_layer_tick).

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
        """Constructor for the bTCP server socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call accept from here.
        """
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)
        self._flag = False
        self._state = None
        self._SEQ = None
        self._ACK = None
        # The data buffer used by lossy_layer_segment_received to move data
        # from the network thread into the application thread. Bounded in size.
        # If data overflows the buffer it will get lost -- that's what window
        # size negotiation should solve.
        # For this rudimentary implementation, we simply hope receive manages
        # to be faster than send.
        self._recvbuf = queue.Queue(maxsize=1000)

    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival, like acknowledging the segment and making the data         ###
    ### available for the application thread that calls to recv can return  ###
    ### the data.                                                           ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###                                                                     ###
    ### Since the implementation is inherently multi-threaded, you should   ###
    ### use a Queue, not a List, to transfer the data to the application    ###
    ### layer thread: Queues are inherently threadsafe, Lists are not.      ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn and client's ack during handshake
            - receiving segments and sending acknowledgements for them,
              making data from those segments available to application layer
            - receiving fin and client's ack during termination
            - any other handling of the header received from the client

        Remember, we expect you to implement this *as a state machine!*
        """

        seq, ack, flags, window, datalen, checksum = self.unpack_segment_header(segment[:10])
        if self._state == BTCPStates.ACCEPTING:
            if flags == 4:  # SYN rcv
                self._state = BTCPStates.SYN_RCVD
                self._ACK = seq + 1
                return
        if self._state == BTCPStates.SYN_SENT:
            if flags == 2:  # ACK rcv
                self._ACK = seq + 1
                self._SEQ = ack
                self._state = BTCPStates.ESTABLISHED
                return


        if self._state == BTCPStates.ESTABLISHED and not flags == 1:     #received segment not indicating end of termination aka normal data
            if seq == self._ACK:                                         #sequence number segment is the expected sequence number meaning no loss of packet
                try:
                    self._recvbuf.put_nowait(segment[10:(10 + datalen)])
                except queue.Full:
                    self._ACK -= 1                                       #decrease ack by one to not acknowledge dropped data   
                self._ACK += 1
                segment = self.build_segment_header(self._SEQ, self._ACK, ack_set=True) + 1008*b'\x00'
                self._lossy_layer.send_segment(segment)
                self.recv()
            else:                                                        #not expected segment, drop it and send same old ack again.
                segment = self.build_segment_header(self._SEQ, self._ACK, ack_set=True) + 1008*b'\x00'
                self._lossy_layer.send_segment(segment)
                self.recv()


        if flags == 1:  # FIN rcv
            self._state = BTCPStates.CLOSING
            print("FIN RCV")
            self.closing()
            return
        if self._state == BTCPStates.CLOSING:
            if flags == 2:  # ACK rcv            	 
                self._state = BTCPStates.CLOSED
                print("ACK RCV")
                return
    
    def closing(self):
        fin_segment = self.build_segment_header(self._SEQ, self._ACK, fin_set=True, ack_set=True)
        self._lossy_layer.send_segment(fin_segment)
        print("FIN ACK SENT")
        return

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received. On the server
        side, you may find you have no actual need for this method. Or maybe
        you do. See if it suits your implementation.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        pass  # present to be able to remove the NotImplementedError without having to implement anything yet.
      
    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### accept connections, receive data, etc. Conceptually, this happens   ###
    ### in "the application thread".                                        ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety. Whether you need to send      ###
    ### segments from the application thread into the lossy layer is up to  ###
    ### you; you may find you can handle all receiving *and* sending of     ###
    ### segments in the lossy_layer_segment_received and lossy_layer_tick   ###
    ### methods.                                                            ###
    ###                                                                     ###
    ### Note that because this is the server socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no send() method available to the applications. You should still    ###
    ### be able to send segments on the lossy layer, however, because       ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

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
        print("SERVER ACCEPTING")
        while self._state:
            
            if self._state == BTCPStates.SYN_RCVD:
                print("SERVER SYN RCV")
                print("SYN SEGMENT: ", self._SEQ, self._ACK)

                break
            continue
        self._SEQ = getrandbits(16)
        syn_ack = self.build_segment_header(self._SEQ, self._ACK, syn_set=True, ack_set=True,
                                            )
        self._lossy_layer.send_segment(syn_ack)
        self._state = BTCPStates.SYN_SENT
        print("SYN ACK SEGMENT: ",self._SEQ,self._ACK)

        print("SERVER SEND ACK")

        
        """while self._state:
            print(self._state)
            if self._state == BTCPStates.ESTABLISHED:
                print("SERVER EST")
                print("EST SEGMENT: ", self._SEQ, self._ACK)

                break
            sleep(0.1)            
            continue
        """

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
        return bytes(data)

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
