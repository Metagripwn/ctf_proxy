import traceback

from src.stream import Stream, TCPStream, HTTPStream
# from src.db_manager import DBManager
import re

class Module():

    '''
    def block_flag_leak_from_non_checker(self, stream: HTTPStream):
        """
        Block flag leaks if response contains flag pattern [A-Z0-9]{31}=
        and the request did not come from checker user-agent
        """
        if not isinstance(stream, HTTPStream):
            return False


        message = stream.current_http_message  # Current response
        if not message or not stream.previous_http_messages:
            return False

        previous_message = stream.previous_http_messages[0]  # Previous request

        # Check if response contains flag pattern
        flag_pattern = rb'[A-Z0-9]{31}='
        has_flag = re.search(flag_pattern, stream.current_message)

        # Check if request user-agent is NOT checker
        user_agent = previous_message.headers.get("user-agent", "").lower()
        is_not_checker = "checker" not in user_agent

        # Block if both conditions are true
        return has_flag and is_not_checker
    '''


    """
    def block_flag_leak_from_single_request(self, stream: Stream):
        flag_pattern = rb'[A-Z0-9]{31}='
        has_flag = re.search(flag_pattern, stream.current_message)
        return has_flag and len(stream.previous_messages) <= 2
    """

    # INFO: uncomment these functions to enable them
    # This module filters SERVER → CLIENT traffic (outgoing responses)

    # HTTP Example - Filter data leaks in responses

    # def block_leak(self, stream: HTTPStream):
    #     """
    #     if responding to /home request and a flag is in the response, block
    #     """
    #     message = stream.current_http_message  # Current response
    #     previous_message = stream.previous_http_messages[0]  # Previous request
    #     return "/home" in previous_message.path and "flag{" in message.raw_body

    # def replace_word(self, stream: HTTPStream):
    #     """replace leet with l33t in server responses"""
    #     # the actual data sent by the socket is stream.current_message
    #     stream.current_message = stream.current_message.replace(b"leet", b"l33t")
    #     return False  # do not block message, just change its contents

    # TCP Example - Filter sensitive data in responses

    # def block_secrets(self, stream: TCPStream):
    #     """block responses containing secrets"""
    #     if b"SECRET_KEY" in stream.current_message:
    #         return True
    #     return False

    # other examples are in the example_functions.py file

    def execute(self, stream: Stream):
        """
        Returns a string that identifies the attack name.
        If None is returned, no attack has been identified inside data.
        If a string is returned, an attack has been identified and the socket will be closed.
        """

        ignored_functions = [] # ["password"]

        attacks = [getattr(Module, attribute) for attribute in dir(Module) if callable(getattr(Module, attribute)) and attribute.startswith('__') is False and attribute != "execute" and attribute not in ignored_functions]

        for attack in attacks:
            try:
                if attack(self, stream):
                    return attack.__name__
            except Exception as e:
                print(f"[filter-error] {attack.__name__}: {type(e).__name__}: {e}")
                traceback.print_exc()
        return None
