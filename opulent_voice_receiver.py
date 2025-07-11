#!/usr/bin/env python3
"""
Opulent Voice Receiver "Postlocutor"
Receives and plays audio and chat from Interlocutor
Opulent Voice frames received over network encapsulated in UDP.

Status:
    Tested on:
        macOS 15.5 Sequoia
        Raspberry Pi OS bookworm
        Windows 11 Pro 24H2
    Likely to work on similar systems.
    Compatible with current Interlocutor builds
Usage:
    python3 opulent_voice_receiver.py
"""

import errno
import queue
import socket
import sounddevice  # not used on macOS or Windows, suppresses errors on Raspberry Pi OS
import struct
import threading
import time
import traceback
from datetime import datetime

import opuslib
import pyaudio
from cobs import cobs
from emoji_data_python import replace_colons
from scapy.all import IP, UDP

# local imports
from callsign_encode import decode_callsign


class OpulentVoiceProtocol:
    """Opulent Voice Protocol Parser"""

    DUMMY_TOKEN_VALUE = 0xBBAADD  # Dummy for authentication token
    HEADER_SIZE = (  # Must be a multiple of 3 bytes for Golay coding
        12  # Station ID (6) + Token (3) +  Reserved (3)
    )

    # Known IP/UDP ports for Opulent Voice
    OPV_ENCAP_UDP_PORT = 57372  # Opulent Voice encapsulation port (not OTA)
    OPV_VOICE_UDP_PORT = 57373  # Opulent Voice Opus voice port
    OPV_TEXT_UDP_PORT = 57374  # Opulent Voice text port
    OPV_CONTROL_UDP_PORT = 57375  # Opulent Voice control port (AAAAA, etc.)

    opus_frame_size_bytes = (
        80  # bytes in an encoded 40ms Opus frame (including a TOC byte)
    )
    opus_packet_size_bytes = opus_frame_size_bytes  # exactly one frame per packet
    rtp_header_bytes = 12  # per RFC3550 (no CSRC, no extension, no padding)
    udp_header_bytes = 8  # per RFC768 (fixed size)
    ip_v4_header_bytes = 20  # per RFC791 (IPv4 only, minimal header without options)
    cobs_overhead_bytes_for_opus = (
        2  # max of 1 byte COBS (since Opus packet < 254 byte) plus a 0 separator
    )
    total_protocol_bytes_for_opus = (
        rtp_header_bytes
        + udp_header_bytes
        + ip_v4_header_bytes
        + cobs_overhead_bytes_for_opus
    )

    @staticmethod
    def parse_frame(frame_data):
        """Parse received Opulent Voice frame"""
        if len(frame_data) < OPVP.HEADER_SIZE:
            return None
        try:
            station_id, token, reserved = struct.unpack(
                ">6s 3s 3s", frame_data[: OPVP.HEADER_SIZE]
            )
            station_id = int.from_bytes(station_id, "big")
            token = int.from_bytes(token, "big")

            if token != OPVP.DUMMY_TOKEN_VALUE:
                return None
            payload = frame_data[OPVP.HEADER_SIZE :]
            return {
                "station_id": station_id,
                "payload": payload,
                "token": token,
                "timestamp": time.time(),
            }
        except struct.error:
            return None


OPVP = OpulentVoiceProtocol  # abbreviation for convenience


class AudioPlayer:
    """Audio playback using PyAudio"""

    def __init__(self, sample_rate=48000, channels=1):
        self.sample_rate = sample_rate
        self.channels = channels
        self.audio = pyaudio.PyAudio()
        self.output_stream = None
        self.audio_queue = queue.Queue(maxsize=5)  # Buffer up to 5 frames
        self.running = False
        # OPUS decoder
        self.decoder = opuslib.Decoder(fs=sample_rate, channels=channels)
        # Statistics
        self.stats = {
            "frames_decoded": 0,
            "frames_played": 0,
            "decode_errors": 0,
            "queue_overflows": 0,
        }
        self.setup_audio_output()

    def setup_audio_output(self):
        """Setup audio output stream"""
        try:
            # Find default output device
            default_output = self.audio.get_default_output_device_info()
            print(
                replace_colons(f":loud_sound: Audio output: {default_output['name']}")
            )
            self.output_stream = self.audio.open(
                format=pyaudio.paInt16,
                channels=self.channels,
                rate=self.sample_rate,
                output=True,
                frames_per_buffer=int(
                    self.sample_rate * 0.04
                ),  # 40ms is 1920 sample frames at 48kHz
                stream_callback=self.audio_callback,
            )
            print(
                f"✓  Audio output ready: {self.sample_rate} samples/second, {self.channels} channel{'s' if self.channels != 1 else ''}"
            )
        except Exception as e:
            print(f"✗ Audio output error: {e}")
            raise

    def audio_callback(self, in_data, frame_count, time_info, status):
        """Audio output callback"""
        if status:
            print(f"Audio playback status: {status}")

        try:
            # Get decoded audio from queue
            if not self.audio_queue.empty():
                audio_data = self.audio_queue.get_nowait()
                self.stats["frames_played"] += 1
                return (audio_data, pyaudio.paContinue)
        except Exception as e:
            print(f"✗ Audio callback error: {e}")
        silence = b"\x00" * (frame_count * 2 * self.channels)
        return (silence, pyaudio.paContinue)

    def decode_and_queue_audio(self, opus_packet):
        """Decode OPUS packet and queue for playback"""
        # print(f"Opus: {opus_packet.hex()}")
        try:
            # Decode OPUS to PCM
            pcm_audio = self.decoder.decode(
                opus_packet, int(self.sample_rate * 0.04), decode_fec=False
            )
            self.stats["frames_decoded"] += 1
            # Add to playback queue
            if self.audio_queue.full():
                # Remove oldest frame if queue is full
                try:
                    self.audio_queue.get_nowait()
                    self.stats["queue_overflows"] += 1
                except queue.Empty:
                    pass
            self.audio_queue.put(pcm_audio)
        except Exception as e:
            self.stats["decode_errors"] += 1
            print(f"✗ OPUS decode error: {e}")

    def start(self):
        """Start audio playback"""
        if self.output_stream:
            self.output_stream.start_stream()
            self.running = True
            print(replace_colons(":musical_note: Audio playback started"))

    def stop(self):
        """Stop audio playback"""
        self.running = False
        if self.output_stream:
            self.output_stream.stop_stream()
            self.output_stream.close()
        self.audio.terminate()
        print(replace_colons(":octagonal_sign: Audio playback stopped"))

    def get_stats(self):
        """Get playback statistics"""
        return self.stats.copy()


class OpulentVoiceReceiver:
    """Main receiver class"""

    def __init__(self, listen_ip="0.0.0.0", listen_port=OPVP.OPV_ENCAP_UDP_PORT):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.socket = None
        self.running = False
        # Components
        self.protocol = OpulentVoiceProtocol()
        self.audio_player = AudioPlayer()
        # Statistics
        self.stats = {
            "packets_received": 0,
            "valid_frames": 0,
            "audio_frames": 0,
            "control_messages": 0,
            "text_messages": 0,
            "invalid_frames": 0,
            "bytes_received": 0,
            "empty_encaps": 0,  # empty encapsulated frames
            "padded_frames": 0,
            "padding_bytes": 0,
        }
        # PTT state tracking
        self.audio_rx_active = False
        self.last_speaker_id = None
        self.last_audio_time = 0
        self.setup_socket()
        self.last_rtp_seq = None
        self.last_rtp_timestamp = None
        self.last_rtp_ssrc = None
        self.cobs_reassembly_buffer = b""
        self.keepalive_state = 1

    def setup_socket(self):
        """Setup UDP listening socket"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.listen_ip, self.listen_port))
            # print(replace_colons(f":globe_with_meridians: Listening on {self.listen_ip}:{self.listen_port}"))
        except Exception as e:
            print(f"✗ Socket setup error: {e}")
            raise

    def process_RTP(self, rtp_header):
        """Process RTP header"""
        if len(rtp_header) < OPVP.rtp_header_bytes:
            print("✗ RTP header too short")
            return
        # Extract RTP fields
        version = (rtp_header[0] >> 6) & 0x03
        if version != 2:
            print(f"✗ Unsupported RTP version: {version}")
            return
        # Check for padding and extension
        padding = (rtp_header[0] >> 5) & 0x01
        if padding:
            print("✗ RTP padding not supported")
            return
        extension = (rtp_header[0] >> 4) & 0x01
        if extension:
            print("✗ RTP extension not supported")
            return
        cc = rtp_header[0] & 0x0F
        if cc > 0:
            print(f"✗ RTP CSRC count {cc} not supported")
            return
        # Extract other fields
        marker = (rtp_header[1] >> 7) & 0x01
        # if marker:
        #     print(replace_colons(":round_pushpin:"), end="", flush=True)

        payload_type = rtp_header[1] & 0x7F
        if payload_type != 96:
            print(f"✗ Unsupported RTP payload type: {payload_type}")
            return

        seq_number = struct.unpack(">H", rtp_header[2:4])[0]
        if (
            self.last_rtp_seq is not None
            and seq_number != (self.last_rtp_seq + 1) % 65536
        ):
            print("RTP sequence restarted")
        self.last_rtp_seq = seq_number

        timestamp = struct.unpack(">I", rtp_header[4:8])[0]
        # if self. is None:
        #     print(f"Rlast_rtp_timestampTP timestamp started at {timestamp}")
        # elif timestamp != self.last_rtp_timestamp + 1920:
        #     print(
        #         f"✗ RTP timestamp mismatch: expected {self.last_rtp_timestamp + 1920}, got {timestamp}"
        #     )
        self.last_rtp_timestamp = timestamp

        ssrc = struct.unpack(">I", rtp_header[8:12])[0]
        # if self.last_rtp_ssrc is None:
        #     print(f"RTP SSRC started at {ssrc}")
        # elif ssrc != self.last_rtp_ssrc:
        #     print(f"RTP SSRC changed to {ssrc}")
        self.last_rtp_ssrc = ssrc

    def process_frame(self, frame_data, sender_addr):
        """Process received Opulent Voice frame"""
        parsed_frame = self.protocol.parse_frame(frame_data)
        if not parsed_frame:
            self.stats["invalid_frames"] += 1
            return
        self.stats["valid_frames"] += 1
        # payload = parsed_frame["payload"]
        self.cobs_process_bytes(parsed_frame)

    def cobs_process_bytes(self, parsed_frame):
        """Process COBS-encoded bytes found in received frame"""
        payload = parsed_frame["payload"]

        # Bytes from multiple COBS packets may be in the payload, process them all.
        # Frame may also contain runs of b"\00" as padding; skip those.
        while len(payload) > 0:
            zero_index = payload.find(b"\x00")  # zero indicates end of COBS packet
            if zero_index >= 0:
                # Found a zero byte, this completes a COBS packet
                self.cobs_reassembly_buffer += payload[
                    :zero_index
                ]  # do not include the zero byte
                self.process_COBS_packet(
                    self.cobs_reassembly_buffer, parsed_frame["station_id"]
                )
                self.cobs_reassembly_buffer = b""  # reset buffer for next COBS packet
                payload = payload[
                    zero_index + 1 :
                ]  # go to next chunk, skipping the zero byte; may be empty
                if len(payload) > 0 and payload[0] == 0:  # this frame contains padding
                    self.stats["padded_frames"] += 1
                while (
                    len(payload) > 0 and payload[0] == 0
                ):  # extra padding bytes are to be ignored
                    payload = payload[1:]
                    self.stats["padding_bytes"] += 1
            else:
                self.cobs_reassembly_buffer += (
                    payload  # accumulate data for COBS packet
                )
                payload = b""

    def process_COBS_packet(self, encoded_payload, sender_id):
        """Process COBS-encoded packet"""
        # print(f"Packet from {decode_callsign(sender_id)}")
        # print(f"encoded: {encoded_payload.hex()}")
        decoded_payload = cobs.decode(encoded_payload)  # decode COBS packet
        # print(f"payload: {decoded_payload.hex()}")

        # entering the world of Scapy in the received packet
        pkt = IP(decoded_payload)
        # pkt.show()
        original_ip_checksum = pkt[IP].chksum
        if UDP in pkt:
            original_udp_checksum = pkt[UDP].chksum
        del pkt[IP].chksum  # Remove original checksum
        pkt = pkt.__class__(bytes(pkt))  # Rebuild the packet, recalculating checksum
        if original_ip_checksum != pkt[IP].chksum:
            print(
                f"✗ IP checksum mismatch: received {original_ip_checksum}, calculated {pkt[IP].chksum}"
            )
        if UDP in pkt:
            del pkt[UDP].chksum  # Remove original checksum
            pkt = pkt.__class__(
                bytes(pkt)
            )  # Rebuild the packet, recalculating checksum
            if original_udp_checksum != pkt[UDP].chksum:
                print(
                    f"✗ UDP checksum mismatch: received {original_udp_checksum}, calculated {pkt[UDP].chksum}"
                )
                return

            udp_port = pkt[UDP].dport
            if udp_port == OPVP.OPV_VOICE_UDP_PORT:
                self.stats["audio_frames"] += 1
                self.last_audio_time = time.time()

                # Handle any RTP protocol processing that's required
                self.process_RTP(bytes(pkt[UDP].payload))

                # Keep screen updated with voice transmission info
                if (not self.audio_rx_active) or sender_id != self.last_speaker_id:
                    self.audio_rx_active = True
                    self.last_speaker_id = sender_id
                    self.current_speech_start_time = time.time()
                    print(
                        replace_colons(f"\n{decode_callsign(sender_id)} :microphone:")
                    )

                # Decode and play audio
                self.audio_player.decode_and_queue_audio(
                    bytes(pkt[UDP].payload)[OPVP.rtp_header_bytes :] + b"\x00"
                )
                # print("🎤", end="", flush=True)
            else:
                if self.audio_rx_active:
                    print(
                        f"Transmission from {decode_callsign(self.last_speaker_id)} ended after{time.time() - self.current_speech_start_time: 0.1f} seconds."
                    )
                    self.audio_rx_active = False

                if udp_port == OPVP.OPV_CONTROL_UDP_PORT:
                    self.stats["control_messages"] += 1
                    payload = bytes(pkt[UDP].payload)
                    message = payload.decode("utf-8", errors="ignore")
                    if message == "PTT_START":
                        pass
                        # print(replace_colons(f":microphone: PTT START from {decode_callsign(sender_id)}"))
                    elif message == "PTT_STOP":
                        pass
                        # print(replace_colons(f"\n:mute: PTT STOP from {decode_callsign(sender_id)}"))
                    elif message[:9] == "KEEPALIVE":
                        print(
                            "\r"
                            + replace_colons(f":clock{self.keepalive_state}:")
                            + "\r",
                            end="",
                            flush=True,
                        )
                        self.keepalive_state += 1
                        if self.keepalive_state > 12:
                            self.keepalive_state = 1
                    else:
                        print(replace_colons(":clipboard:") + f" Control: {message}")

                elif udp_port == OPVP.OPV_TEXT_UDP_PORT:
                    self.stats["text_messages"] += 1
                    payload = bytes(pkt[UDP].payload)
                    text_message = payload.decode("utf-8", errors="ignore")
                    print(
                        decode_callsign(sender_id)
                        + replace_colons(f" :speech_balloon: {text_message}")
                    )
                else:
                    print(
                        replace_colons(
                            f":question: Unknown UDP destination port: {udp_port}"
                        )
                    )

    def listen_loop(self):
        """Main listening loop"""
        print(replace_colons(":ear: Listening for Opulent Voice packets..."))
        while self.running:
            try:
                # Receive packet
                data, sender_addr = self.socket.recvfrom(4096)
                if not data:
                    self.stats["empty_encaps"] += 1
                    continue  # Skip empty packets
                self.stats["packets_received"] += 1
                self.stats["bytes_received"] += len(data)
                # Process frame
                self.process_frame(data, sender_addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only print error if we're supposed to be running
                    print(f"✗ Receive error: {e}")
                    print(traceback.format_exc())

    def print_status(self):
        """Print current status"""
        now = datetime.now().strftime("%H:%M:%S")
        audio_stats = self.audio_player.get_stats()
        print(replace_colons(f"\n:bar_chart: Status at {now}:"))
        print(f"   Packets received: {self.stats['packets_received']}")
        print(f"   Valid frames: {self.stats['valid_frames']}")
        print(f"   Audio frames: {self.stats['audio_frames']}")
        print(f"   Text messages: {self.stats['text_messages']}")
        print(f"   Control messages: {self.stats['control_messages']}")
        print(f"   OPUS decoded: {audio_stats['frames_decoded']}")
        print(f"   Audio played: {audio_stats['frames_played']}")
        print(f"   Decode errors: {audio_stats['decode_errors']}")
        print(f"   Empty encapsulated frames: {self.stats['empty_encaps']}")
        print(f"   Frames with padding bytes: {self.stats['padded_frames']}")
        print(f"   Padding bytes between COBS packets: {self.stats['padding_bytes']}")
        if self.last_audio_time > 0:
            time_since_audio = time.time() - self.last_audio_time
            print(f"   Last audio: {time_since_audio:.1f}s ago")

    def start(self):
        """Start the receiver"""
        self.running = True
        self.audio_player.start()
        # Start listening in a separate thread
        self.listen_thread = threading.Thread(target=self.listen_loop)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        print(replace_colons(":rocket: Opulent Voice Receiver started"))

    def stop(self):
        """Stop the receiver"""
        self.running = False
        self.audio_player.stop()
        if self.socket:
            self.socket.close()
        print(replace_colons(":octagonal_sign: Receiver stopped"))


# Main execution
if __name__ == "__main__":
    print("=" * 50)
    print(replace_colons(":studio_microphone: Opulent Voice Receiver"))
    print("=" * 50)
    print(
        replace_colons(
            f":satellite_antenna: Will listen on port {OPVP.OPV_ENCAP_UDP_PORT} for UDP-encapsulated Opulent Voice frames"
        )
    )
    print(
        replace_colons(":loud_sound: Make sure your speakers/headphones are connected!")
    )
    try:
        # Create and start receiver
        receiver = OpulentVoiceReceiver(listen_port=OPVP.OPV_ENCAP_UDP_PORT)
        receiver.start()
        print(
            replace_colons(
                ":white_check_mark: Receiver ready! Waiting for transmissions..."
            )
        )
        print(replace_colons(":bar_chart: Press Ctrl+C to show stats and exit"))
        # Status updates every 10 seconds
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(replace_colons("\n:bar_chart: Final Statistics:"))
        receiver.print_status()
        print(replace_colons("\n:wave: Thanks for using Opulent Voice Receiver!"))
    except Exception as e:
        if e.errno == errno.EADDRINUSE:  # Address already in use
            print(
                replace_colons(
                    ":warning: Port already in use! Please stop any other Opulent Voice receivers."
                )
            )
        else:
            print(f"✗ Error: {e}")
            print(traceback.format_exc())
    finally:
        if "receiver" in locals() and receiver.running:
            receiver.stop()
