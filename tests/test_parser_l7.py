"""parser.detect_l7 / extract_l7_fields contracts for BitTorrent handshakes."""
from __future__ import annotations

import os

import parser as sgparser

INFO = bytes(range(20))
PEER = b"-DL3790-" + b"abcdefghijkl"
RES = bytes.fromhex("0000000008180001")
DL = (b"\x13" + bytes.fromhex("49020f570d73660a167d264957110000000000")
      + RES + INFO + PEER)
STD = b"\x13BitTorrent protocol" + bytes(8) + INFO + b"-qB4250-" + b"x" * 12


def test_dl_handshake_is_bittorrent():
    assert len(DL) == 68
    assert sgparser.detect_l7(DL, 51021, 14762) == sgparser.L7_BITTORRENT


def test_dl_fields():
    f = sgparser.extract_l7_fields(sgparser.L7_BITTORRENT, DL)
    assert f["variant"] == "dl"
    assert f["peer_id"].startswith("-DL3790-")
    assert f["info_hash"] == INFO.hex()


def test_standard_fields_peer_id_is_bytes_48_to_68():
    f = sgparser.extract_l7_fields(sgparser.L7_BITTORRENT, STD)
    assert "variant" not in f
    assert f["peer_id"].startswith("-qB4250-")
    assert f["info_hash"] == INFO.hex()


def test_other_pstr_with_azureus_peer_id_is_bittorrent():
    p = b"\x13" + b"Q" * 19 + bytes(8) + INFO + b"-ZZ0001-" + b"y" * 12
    assert sgparser.detect_l7(p, 1, 2) == sgparser.L7_BITTORRENT
    assert sgparser.extract_l7_fields(sgparser.L7_BITTORRENT, p)["variant"] == "other"


def test_random_68_bytes_are_not_bittorrent():
    hits = sum(sgparser.detect_l7(b"\x13" + os.urandom(67), 1, 2) == sgparser.L7_BITTORRENT
               for _ in range(2000))
    assert hits == 0


# Levin (Monero P2P): real payloads from the 2025-10 port 47373 burst.
LEVIN_SPLIT = bytes.fromhex("0121010101010101")
LEVIN_HEADER = bytes.fromhex("01210101010101010A0000000000000001EB0300000000000"
                             "0010000000100000001110101010102010100")


def test_levin_signature_alone_is_levin_with_a_field():
    # The split header must still give fields, or its packet gets no
    # l7_events row and the verdict stage cannot see the sender.
    assert sgparser.detect_l7(LEVIN_SPLIT, 51000, 47373) == sgparser.L7_LEVIN
    f = sgparser.extract_l7_fields(sgparser.L7_LEVIN, LEVIN_SPLIT)
    assert f == {"header": "split"}


def test_levin_header_gives_command():
    assert sgparser.detect_l7(LEVIN_HEADER, 51000, 47373) == sgparser.L7_LEVIN
    f = sgparser.extract_l7_fields(sgparser.L7_LEVIN, LEVIN_HEADER)
    assert f == {"command": 1003}


def test_levin_name_matches_lib():
    from sg import lib
    assert lib.L7_NAME[sgparser.L7_LEVIN] == sgparser.L7_NAME[sgparser.L7_LEVIN] == "levin"
