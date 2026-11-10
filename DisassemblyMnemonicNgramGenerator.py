import logging
import os
import time
from collections import deque
import mmh3
from Disassemblies.Disassembly import DisassemblyBinary, DisassemblyInstruction

# Set logging for this module
logger = logging.getLogger(os.path.splitext(os.path.basename(__file__))[0])
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


class DisassemblyMnemonicNgramGenerator(object):

    """
    Generates a set of mnemonic n-grams that are derived from a disassembled binary
    """

    def __init__(self, binary_name, binary_sha256_hash, linear_list_of_disassembly_instructions, n=5):

        self._binary_name = binary_name

        self._binary_sha256_hash = binary_sha256_hash

        self._linear_list_of_disassembly_instructions = linear_list_of_disassembly_instructions

        self._n = n

        self._hashed_ngram_set = None

    def _generate_n_gram_set(self):

        """
        Generate a set of n_grams from the linear_list_of_disassembly_instructions, where each element in the
        set is tuple of size n.
        Example: Suppose linear_list has 6 instructions: push, pop, mov, xor, add, sub.
                 If n=3, then the first n-gram would be the following tuple: (push,pop,mov)
                 The next n-gram would then be the following tuple: (pop,mov,xor)
                 Then the next would be the following tuple: (mov,xor,add)

        :return: A set, where each element of the set is a n-gram represented as a tuple of size n
        """
        n_gram_set = set()

        instructions = self._linear_list_of_disassembly_instructions

        # Slide a window of size self._n across the full instruction list.
        # Each position yields one tuple of n consecutive mnemonics.
        for i in range(len(instructions) - self._n + 1):
            n_gram_tuple = tuple(
                instructions[i + j].mnemonic for j in range(self._n)
            )
            n_gram_set.add(n_gram_tuple)

        return n_gram_set

    def generate_set_of_hashed_n_grams(self):

        """
        Generate a hashed set of ngrams using mmh3 hash algorithm
        :return: hashed set of ngrams using mmh3 hash algorithm
        """

        n_grams_hashed_set = set()

        # First get the set of n-gram tuples
        n_gram_set = self._generate_n_gram_set()

        # Hash each n-gram tuple using mmh3.
        # Encode every mnemonic string to bytes, concatenate them, then hash.
        for n_gram_tuple in n_gram_set:
            bytes_to_hash = b"".join([mnemonic.encode() for mnemonic in n_gram_tuple])
            hash_value = mmh3.hash(bytes_to_hash)
            n_grams_hashed_set.add(hash_value)

        return n_grams_hashed_set

    @classmethod
    def from_disassembly_file(cls, disassembly_binary_file_path):

        # Generate the disassembly binary object from the file path
        disassembly_binary = DisassemblyBinary.deserialize_from_file(disassembly_binary_file_path)

        # SHA-256 hash of binary
        binary_sha256_hash = disassembly_binary.binary_sha256_hash

        # Name of the binary
        binary_name = disassembly_binary.binary_name

        # Iterate through each function → basic blocks → instructions
        # to produce a flat linear list of all DisassemblyInstruction objects
        linear_list_of_disassembly_instructions = [
            disassembly_instruction
            for disassembly_function in disassembly_binary.disassembly_func_list
            for disassembly_basic_block in disassembly_function.disassembly_basicblock_list
            for disassembly_instruction in disassembly_basic_block.disassembly_instruct_list
        ]

        disassembly_mnemonic_ngram_generator = cls(
            binary_name,
            binary_sha256_hash,
            linear_list_of_disassembly_instructions
        )

        return disassembly_mnemonic_ngram_generator

    @property
    def binary_name(self):
        return self._binary_name

    @property
    def binary_sha256_hash(self):
        return self._binary_sha256_hash

    @property
    def hashed_ngram_set(self):
        if self._hashed_ngram_set is None:
            self._hashed_ngram_set = self.generate_set_of_hashed_n_grams()
        return self._hashed_ngram_set


def test_harness():
    logger.info("*******Test Harness*****************")

    TEST_DISASSEMBLY_A_PB_FILE_PATH = "disassembly_protos/explorer.exe_Disassembly_70506db080603a6a35004e92edb2ed5bfa51fac9e065e50b3640eb46ef528d48.pb.z"

    start_time = time.time()

    disass_mnemonic_ngram_generator = DisassemblyMnemonicNgramGenerator.from_disassembly_file(
        TEST_DISASSEMBLY_A_PB_FILE_PATH
    )

    disass_mnemonic_ngram_generator.generate_set_of_hashed_n_grams()

    end_time = time.time()
    elapsed_time = end_time - start_time
    logger.info("Elapsed time to generate n-grams for {}: {}".format(
        disass_mnemonic_ngram_generator.binary_name, elapsed_time
    ))

    logger.info("*******END Test Harness**************")


if __name__ == "__main__":
    test_harness()
