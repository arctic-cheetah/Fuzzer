from fuzzer_core import Fuzzer
from typing import Callable, List



class JPEG_Fuzzer(Fuzzer):
    def __init__(self, path_to_input:str, binary_path:str):
        super().__init__(path_to_input, binary_path)
        self.mutators = [
            magic,
        ]


    def mutate(self, data: bytes) -> bytes:
        """ since this is an image format we may need to overload """
        im = data
        return im # TODO:
         


############################## mutators #################################

def huge(im: bytes):
    """ mess with the size large """

    pass # TODO:

def magic(im:bytes):
    """ totally not a jpeg """
    pass # TODO:

def dimension(im):
    """ what a weirdly sized image """
    pass# TODO:



def dct_hell(im):
    """ discrete cosine transform, but mess it up a bit """
    pass# TODO:


def seg_fault(im):
    """ change a random segment size """
    pass# TODO:


def marker_corrupt(im):
    """
        there are many markers SOI, EOI, SOF, DQT
    """
    pass# TODO:



def jpeg_2000(im):
    """  """

