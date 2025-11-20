from fuzzer_core import Fuzzer
from typing import Callable, List
from jpeg_core import JPEG, SEGMENTS
import random


class JPEG_Fuzzer(Fuzzer):
    def __init__(self, path_to_input:str, binary_path:str):
        super().__init__(path_to_input, binary_path)
        self.mutators = [
            huge,
            smol,
            lots_of_stuff_here,
            marker_corrupt,
            dimension,

        ]
        self.corpus: List[JPEG] = []



    def mutate(self, data: JPEG, num=0) -> JPEG:
        """ since this is an image format we may need to overload """

        mutation = random.choice(self.mutators)(data)
        num -= 1
        return mutation if num <= 0 else self.mutate(mutation)

    def make_payload(self, seed)
        if not self.corpus:
            self.corpus += [JPEG(seed)]
        img = random.choice(self.corpus)
        return self.mutate(img, num=random.randint(1,4)).to_bytes()

    # haven't decided if this is really a good strategy without beter coverage info
    # def log_crash(self, data: bytes):
    #     self.corpus += [JPEG(data)]
    #     return super().log_crash(data)


############################## mutators #################################

def huge(im: JPEG):
    """ mess with the size, make it massive, loop ofer sof markers and enlarge to max size.
    Marker Identifier               2 bytes     0xff, 0xc0 to identify SOF0 marker
    Length                          2 bytes     This value equals to 8 + components*3 value
    Data precision                  1 byte      This is in bits/sample, usually 8 (12 and 16 not supported by most software).
    Image height                    2 bytes     This must be > 0
    Image Width                     2 bytes     This must be > 0
    Number of components            1 byte      Usually 1 = grey scaled, 3 = color YcbCr or YIQ, 4 = color CMYK
    Each component                  3 bytes     Read each component data of 3 bytes. It contains,
                                                (component Id(1byte)(1 = Y, 2 = Cb, 3 = Cr, 4 = I, 5 = Q),
                                                sampling factors (1byte) (bit 0-3 vertical., 4-7 horizontal.),
                                                quantization table number (1 byte)).
    """
    sofi = [val for key, val in im.segments.items() if key.startswith("SOI")]
    for i in sofi:
        im.data[i+5:i+9] = 0xff

def smol(im:JPEG):
    """ tiny """
    sofi = [val for key, val in im.segments.items() if key.startswith("SOI")]
    for i in sofi:
        im.data[i+5:i+9] = 0

def lots_of_stuff_here(im: JPEG):
    """ number of components """
    if "SOS" in im.segments:
        im.data[im.segments["SOS"] + 5] = random.randint(0,255)

def magic(im: JPEG):
    """ totally not a jpeg """
    pass # TODO:

def dimension(im: JPEG):
    """ what a weirdly sized image """
    sofi = [val for key, val in im.segments.items() if key.startswith("SOI")]
    random_ints = [random.randint(0, 255) for _ in range(4)]
    for i in sofi:
        im.data[i+5:i+9] = random_ints



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
    marker = random.choice(im.segments)
    im.data[marker] = 0


def jpeg_2000(im):
    """  """
