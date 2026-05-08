from src.http_parsing import HttpMessageParser, HttpMessage
from collections import deque

# class NoIndexError(deque):
#     def __getitem__(self, key):
#         try:
#             return super().__getitem__(key)
#         except:
#             return b""
        
class Stream():
    def __init__(self, max_stored_messages: int = 50, max_message_size: int = 65535):
        self.current_message = b""
        self.previous_messages = deque(maxlen=max_stored_messages)
        self._max_message_size = max_message_size
        self.last_response_sent_at: float | None = None
        self.rtt_samples: deque[int] = deque(maxlen=32)
        self.min_rtt_us: int | None = None
        self.is_likely_checker: bool | None = None

    def record_rtt_sample(self, gap_us: int, threshold_us: int | None):
        """Record an inter-request gap (microseconds). Updates min and label."""
        self.rtt_samples.append(gap_us)
        if self.min_rtt_us is None or gap_us < self.min_rtt_us:
            self.min_rtt_us = gap_us
        if threshold_us is not None and self.min_rtt_us < threshold_us:
            self.is_likely_checker = True
        elif threshold_us is not None and self.is_likely_checker is None:
            self.is_likely_checker = False

    def set_current_message(self, data: bytes):
        pass

class TCPStream(Stream):
    """
    Class for storing TCP data of a single connection.

    current_message: current message as bytes received (this will be sent to the socket, it can be modified)

    previous_messages: latest max_stored_messages messages of the connection before current_message (newest to oldest)
    """
    def set_current_message(self, data: bytes):
        if len(self.current_message) <= self._max_message_size:
            self.previous_messages.appendleft(self.current_message)
        else:
            self.previous_messages.appendleft(self.current_message[-self._max_message_size])
        self.current_message = data
class HTTPStream(Stream):
    """
    Class for storing HTTP data of a single connection.

    current_message: current message as bytes received (this will be sent to the socket, it can be modified)

    previous_messages: latest max_stored_messages messages of the connection before current_message (newest to oldest)

    current_http_message: current_message parsed as HttpMessage

    previous_http_messages: previous_messages parsed as HttpMessage (newest to oldest)
    """
    def __init__(self, max_stored_messages: int = 50, max_message_size: int = 65535):
        super().__init__(max_stored_messages, max_message_size)
        self.current_http_message = None
        self.previous_http_messages: deque[HttpMessage] = deque(maxlen=max_stored_messages)

    def set_current_message(self, data: bytes):
        if len(self.current_message) <= self._max_message_size:
            self.previous_messages.appendleft(self.current_message)            
        else:
            self.previous_messages.appendleft(self.current_message[:self._max_message_size])
        
        self.current_message = data
        
        try:            
            self.previous_http_messages.appendleft(HttpMessageParser(self.previous_messages[0]).to_message())
            self.current_http_message = HttpMessageParser(data).to_message()
        except Exception as e:
            self.current_http_message = None
            print("Error in HTTP parsing:", str(e))