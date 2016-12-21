#!/usr/bin/python3

import logging
import sys
import argparse
import os
import struct


logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

BLOCK_HEADER_SIZE = 16
BLOCK_END_MARKER_SIZE = 4


def decrypt(data, key):
    # Apply Ceasar cypher on the data.

    # Pad the key to the size of the data.
    pad = len(data)//len(key) + 1
    key = key * pad
    key = key[:len(data)]

    # XOR the data and the key.
    decoded_data = b''
    for (x,y) in zip(data, key):
        decoded_data += chr(x^y).encode("utf-8")
    return decoded_data


def decode_archive(local_user, peer_user, archive_filename):
    logger.info("Decoding file [%s] of user [%s] with [%s].", archive_filename, local_user, peer_user)
    logger.debug("Opening file [%s] of size [%s] bytes.", archive_filename, os.path.getsize(archive_filename))

    total_read = 0
    archive_file = open(archive_filename, "rb")
    while True:
        # Read blocke header.
        header_bytes = archive_file.read(BLOCK_HEADER_SIZE)
        if len(header_bytes) == 0:
            break
        timestamp, field2, field3, size = struct.unpack("@iiii", header_bytes)

        # Read the message of length specified in the header.
        data_bytes = archive_file.read(size)

        end_marker_bytes = archive_file.read(BLOCK_END_MARKER_SIZE)
        end_marker = struct.unpack("@i", end_marker_bytes)
        total_read += BLOCK_HEADER_SIZE + len(data_bytes) + BLOCK_END_MARKER_SIZE

        print(timestamp, field2, field3, decrypt(data_bytes, local_user.encode("utf-8")).decode("utf-8"))

    archive_file.close()


def parse_messages_peer(local_user, peer_user, peer_tree, args):
    logger.debug("Parsing logs dir for user [%s] with peer [%s]", local_user, peer_user)
    for k, v in peer_tree.items():
        # v should be a leaf of the tree (a file).
        if not v:
            # Rebuild the path to the file.
            dat_file = os.path.join(args.root, local_user, "Archive", "Messages", peer_user, k)
            if os.path.isfile(dat_file):
                decode_archive(local_user, peer_user, dat_file)


def parse_messages(local_user, messages_tree, args):
    logger.debug("Parsing Messages dir for user [%s]", local_user)
    for k, v in messages_tree.items():
        # Keys with None values are not profiles or are boken.
        if v:
            parse_messages_peer(local_user, k, v, args)


def parse_archive(local_user, archive_tree, args):
    logger.debug("Parsing Archive dir for user [%s]", local_user)
    if "Messages" in archive_tree:
        messages = archive_tree.get("Messages")
        # If Messages dir has contents, parse them.
        if messages:
            parse_messages(local_user, messages, args)


def parse_profile(local_user, profile_tree, args):
    logger.debug("Parsing tree for user [%s]", local_user)
    if "Archive" in profile_tree:
        # If Archive dir has contents, parse them.
        archive = profile_tree.get("Archive")
        if archive:
            parse_archive(local_user, archive, args)


def parse_profiles(profiles, args):
    logger.debug("Parsing profiles [%s]", list(profiles.keys()))
    for k, v in profiles.items():
        # Keys with None values are not profiles or are boken.
        if v:
            parse_profile(k, v, args)


def parse_dir_tree(path):
    path = os.path.abspath(path)
    if os.path.isdir(path):
        dir_dict = {}
        for filename in os.listdir(path):
            sub_path = os.path.join(path, filename)
            dir_dict[filename] = parse_dir_tree(sub_path)
        return dir_dict
    else:
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="Yahoo Messenger archive decoder.")
    parser.add_argument("root", help="Location of Profiles directory")
    parser.add_argument("--user", help="Decode archives for specific user.", default=None)
    parser.add_argument("--peer", help="Decode archives for peer.", default=None)
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    if os.path.isdir(args.root):
        profiles_path = os.path.abspath(args.root)
        print(profiles_path)
        logger.debug("Parsing Profiles directory: [%s]", profiles_path)
        dir_tree = parse_dir_tree(profiles_path)
        parse_profiles(dir_tree, args)
    else:
        logger.error("Specified Profiles directory does not exist.")
        sys.exit(1)


if __name__ == "__main__":
    main()
