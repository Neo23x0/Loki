#!/usr/bin/python
#
# Double Pulsar Checks
# https://github.com/countercept/doublepulsar-detection-script/blob/master/detect_doublepulsar_rdp.py
# Author: Luke Jennings (luke.jennings@countercept.com - @jukelennings)
# XOR Key calculation provided by https://github.com/FireFart
#
# Modified version that allows to be used as library
#
# Copyright (c) 2017, Countercept (https://countercept.com)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import binascii
import socket
import ssl
import struct

class DoublePulsar(object):

    def __init__(self, ip="127.0.0.1", timeout=None, verbose=False):
        self.ip = ip
        self.timeout = timeout
        self.verbose = verbose

        # RDP
        # Packets
        self.ssl_negotiation_request = binascii.unhexlify("030000130ee000000000000100080001000000")
        self.non_ssl_negotiation_request = binascii.unhexlify("030000130ee000000000000100080000000000")
        self.non_ssl_client_data = binascii.unhexlify(
            "030001ac02f0807f658201a00401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201020482013f000500147c00018136000800100001c00044756361812801c0d800040008000005000401ca03aa09080000b01d0000000000000000000000000000000000000000000000000000000000000000000007000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca01000000000018000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000004c00c00110000000000000002c00c001b0000000000000003c0380004000000726470647200000000008080726470736e640000000000c0647264796e766300000080c0636c6970726472000000a0c0")
        self.ssl_client_data = binascii.unhexlify(
            "030001ac02f0807f658201a00401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201020482013f000500147c00018136000800100001c00044756361812801c0d800040008000005000401ca03aa09080000b01d0000000000000000000000000000000000000000000000000000000000000000000007000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca01000000000018000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000100000004c00c00110000000000000002c00c001b0000000000000003c0380004000000726470647200000000008080726470736e640000000000c0647264796e766300000080c0636c6970726472000000a0c0")
        self.ping_packet = binascii.unhexlify("0300000e02f0803c443728190200")

        # SMB
        # Packets
        self.negotiate_protocol_request = binascii.unhexlify(
            "00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
        self.session_setup_request = binascii.unhexlify(
            "00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
        self.tree_connect_request = binascii.unhexlify(
            "00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
        self.trans2_session_setup = binascii.unhexlify(
            "0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")

    def check_ip_smb(self):

        # Connect to socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(self.timeout) if self.timeout else None)
        host = self.ip
        port = 445
        s.connect((host, port))

        # Send/receive negotiate protocol request
        if self.verbose:
            print("Sending negotiation protocol request")
        s.send(self.negotiate_protocol_request)
        s.recv(1024)

        # Send/receive session setup request
        if self.verbose:
            print("Sending session setup request")
        s.send(self.session_setup_request)
        session_setup_response = s.recv(1024)

        # Extract user ID from session setup response
        user_id = session_setup_response[32:34]
        if self.verbose:
            print("User ID = %s" % struct.unpack("<H", user_id)[0])

        # Replace user ID in tree connect request packet
        modified_tree_connect_request = list(self.tree_connect_request)
        modified_tree_connect_request[32] = user_id[0]
        modified_tree_connect_request[33] = user_id[1]
        modified_tree_connect_request = "".join(modified_tree_connect_request)

        # Send tree connect request
        if self.verbose:
            print("Sending tree connect")
        s.send(modified_tree_connect_request)
        tree_connect_response = s.recv(1024)

        # Extract tree ID from response
        tree_id = tree_connect_response[28:30]
        if self.verbose:
            print("Tree ID = %s" % struct.unpack("<H", tree_id)[0])

        # Replace tree ID and user ID in trans2 session setup packet
        modified_trans2_session_setup = list(self.trans2_session_setup)
        modified_trans2_session_setup[28] = tree_id[0]
        modified_trans2_session_setup[29] = tree_id[1]
        modified_trans2_session_setup[32] = user_id[0]
        modified_trans2_session_setup[33] = user_id[1]
        modified_trans2_session_setup = "".join(modified_trans2_session_setup)

        # Send trans2 sessions setup request
        if self.verbose:
            print("Sending trans2 session setup")
        s.send(modified_trans2_session_setup)
        final_response = s.recv(1024)

        s.close()

        # Check for 0x51 response to indicate DOUBLEPULSAR infection
        if final_response[34] == "\x51":
            signature = final_response[18:26]
            signature_long = struct.unpack('<Q', signature)[0]
            key = calculate_doublepulsar_xor_key(signature_long)
            return True, "DoublePulsar SMB implant detected XOR KEY: %s " % hex(key)
        else:
            return False, "No presence of DOUBLEPULSAR SMB implant"

    def check_ip_rdp(self):

        # Connect to socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(self.timeout) if self.timeout else None)
        host = self.ip
        port = 3389
        s.connect((host, port))

        # Send/receive negotiation request
        if self.verbose:
            print("Sending negotiation request")
        s.send(self.ssl_negotiation_request)
        negotiation_response = s.recv(1024)

        # Determine if server has chosen SSL
        if len(negotiation_response) >= 19 and negotiation_response[11] == "\x02" and negotiation_response[15] == "\x01":
            if self.verbose:
                print("Server chose to use SSL - negotiating SSL connection")
            sock = ssl.wrap_socket(s)
            s = sock

            # Send/receive ssl client data
            if self.verbose:
                print("Sending SSL client data")
            s.send(self.ssl_client_data)
            s.recv(1024)

        # Server explicitly refused SSL
        elif len(negotiation_response) >= 19 and negotiation_response[11] == "\x03" and negotiation_response[15] == "\x02":
            if self.verbose:
                print("Server explicitly refused SSL, reconnecting")

            # Re-connect
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(self.timeout) if self.timeout else None)
            s.connect((host, port))

            # Send/receive non-ssl negotiation request
            if self.verbose:
                print("Sending non-ssl negotiation request")
            s.send(self.non_ssl_negotiation_request)
            s.recv(1024)

        # Server requires NLA which implant does not support
        elif len(negotiation_response) >= 19 and negotiation_response[11] == "\x03" and negotiation_response[15] == "\x05":
            s.close()
            return False, "Server requires NLA, which DOUBLEPULSAR does not support"

        # Carry on non-ssl
        else:
            # Send/receive non-ssl client data
            if self.verbose:
                print("Sending client data")
            s.send(self.non_ssl_client_data)
            s.recv(1024)

        # Send/receive ping
        if self.verbose:
            print("Sending ping packet")
        s.send(self.ping_packet)

        # Non-infected machines terminate connection, infected send a response
        try:
            ping_response = s.recv(1024)

            if len(ping_response) == 288:
                return True, "DoublePulsar SMB implant detected"
            else:
                return False, "Status Unknown - Response received but length was %d not 288" % (len(ping_response))

            s.close()
        except socket.error as e:
            return False, "No presence of DOUBLEPULSAR RDP implant"


def calculate_doublepulsar_xor_key(s):
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x