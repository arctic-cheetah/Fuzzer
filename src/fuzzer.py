import json
import random


class Fuzzer:
    def __init__(self, path_to_input: str):
        self.corpus = open(
            path_to_input, "rw"
        )  # doesn't have to be a file, can be loaded into memory, the
        self.mutators = [
            # add more as we make strategies
        ]

    def generate_rand_str(
        self, max_length: int = 100, char_start: int = 32, char_range: int = 32
    ) -> str:
        """adapted from fuzzing book"""
        out = ""
        chars: range = random.randrange(0, max_length + 1)
        for i in chars:
            out += chr(random.randrange(char_start, char_start + char_range))
        return out

    def replace_rand_str(self):
        pass

    def add_to_corpus(self, to_add: str):
        self.corpus.write("\n" + to_add)

    def __del__(self):
        self.corpus.close()

    def mutate(self, s: str, repeat=1):
        """the function the harness will call, to produce an input"""

        mutator = random.choice(self.mutators)
        mutation = mutator(s)
        if repeat == 1:
            return mutation
        return self.mutate(mutation, repeat - 1)


class JSON_Mutational_Fuzzer(Fuzzer):

    def __init__(self, path_to_input):
        super().__init__(path_to_input)
        self.grammar = json.load(self.corpus.read())  # assuming one input intitially
        self.mutators = [
            self.delete_random_field,
            self.change_a_field,
        ]

    def delete_random_field(self):
        pass

    def change_a_field(self):
        pass


# TODO: Do mutational fuzzer for XML, JPEG, and other file types from assignment


class XML_Mutational_Fuzzer(Fuzzer):

    def __init__(self, path_to_input):
        super().__init__(path_to_input)
        self.grammar = self.corpus.read()  # assuming one input intitially
        self.mutators = [
            self.delete_random_field,
            self.change_a_field,
        ]

    def delete_random_field(self):
        pass

    def change_a_field(self):
        pass
