from collections import OrderedDict
import numpy as np
from dataclasses import dataclass, field
# source: https://www.disktuna.com/list-of-jpeg-markers/
#   Hex 	  Marker 	  Marker Name 	    Description
SEGMENTS = {
    0xC0:     "SOF0", 	# Start of Frame 0 	Baseline DCT
    0xC1:     "SOF1", 	# Start of Frame 1 	Extended Sequential DCT
    0xC2:     "SOF2", 	# Start of Frame 2 	Progressive DCT
    0xC3:     "SOF3", 	# Start of Frame 3 	Lossless (sequential)
    0xC4:     "DHT", 	# Define Huffman Table
    0xC5:     "SOF5", 	# Start of Frame 5 	Differential sequential DCT
    0xC6:     "SOF6", 	# Start of Frame 6 	Differential progressive DCT
    0xC7:     "SOF7", 	# Start of Frame 7 	Differential lossless (sequential)
    0xC8:     "JPG", 	# JPEG Extensions
    0xC9:     "SOF9", 	# Start of Frame 9 	Extended sequential DCT, Arithmetic coding
    0xCA:     "SOF10", 	# Start of Frame 10 	Progressive DCT, Arithmetic coding
    0xCB:     "SOF11", 	# Start of Frame 11 	Lossless (sequential), Arithmetic coding
    0xCC:     "DAC", 	# Define Arithmetic Coding
    0xCD:     "SOF13", 	# Start of Frame 13 	Differential sequential DCT, Arithmetic coding
    0xCE:     "SOF14", 	# Start of Frame 14 	Differential progressive DCT, Arithmetic coding
    0xCF:     "SOF15", 	# Start of Frame 15 	Differential lossless (sequential), Arithmetic coding
    0xD0:     "RST0", 	# Restart Marker 0
    0xD1:     "RST1", 	# Restart Marker 1
    0xD2:     "RST2", 	# Restart Marker 2
    0xD3:     "RST3", 	# Restart Marker 3
    0xD4:     "RST4", 	# Restart Marker 4
    0xD5:     "RST5", 	# Restart Marker 5
    0xD6:     "RST6", 	# Restart Marker 6
    0xD7:     "RST7", 	# Restart Marker 7
    0xD8:     "SOI", 	# Start of Image
    0xD9:     "EOI", 	# End of Image
    0xDA:     "SOS", 	# Start of Scan
    0xDB:     "DQT", 	# Define Quantization Table
    0xDC:     "DNL", 	# Define Number of Lines 	(Not common)
    0xDD:     "DRI", 	# Define Restart Interval
    0xDE:     "DHP", 	# Define Hierarchical Progression 	(Not common)
    0xDF:     "EXP", 	# Expand Reference Component 	(Not common)
    0xE0:     "APP0", 	# Application Segment 0 	JFIF – JFIF JPEG image, AVI1 – Motion JPEG (MJPG)
    0xE1:     "APP1", 	# Application Segment 1 	EXIF Metadata, TIFF IFD format, JPEG Thumbnail (160×120), Adobe XMP
    0xE2:     "APP2", 	# Application Segment 2 	ICC color profile, FlashPix
    0xE3:     "APP3", 	# Application Segment 3 	(Not common), JPS Tag for Stereoscopic JPEG images
    0xE4:     "APP4", 	# Application Segment 4 	(Not common)
    0xE5:     "APP5", 	# Application Segment 5 	(Not common)
    0xE6:     "APP6", 	# Application Segment 6 	(Not common), NITF Lossles profile
    0xE7:     "APP7", 	# Application Segment 7 	(Not common)
    0xE8:     "APP8", 	# Application Segment 8 	(Not common)
    0xE9:     "APP9", 	# Application Segment 9 	(Not common)
    0xEA:     "APP10", 	# Application Segment 10  PhoTags 	(Not common) ActiveObject (multimedia messages / captions)
    0xEB:     "APP11", 	# Application Segment 11 	(Not common), HELIOS JPEG Resources (OPI Postscript)
    0xEC:     "APP12", 	# Application Segment 12 	Picture Info (older digicams), Photoshop Save for Web: Ducky
    0xED:     "APP13", 	# Application Segment 13 	Photoshop Save As: IRB, 8BIM, IPTC
    0xEE:     "APP14", 	# Application Segment 14 	(Not common)
    0xEF:     "APP15", 	# Application Segment 15 	(Not common)
    0xF0:     "JPG0",           # JPEG Extension 0 …
    0xF1:     "JPG1",           # JPEG Extension 1 …
    0xF2:     "JPG2",           # JPEG Extension 2 …
    0xF3:     "JPG3",           # JPEG Extension 3 …
    0xF4:     "JPG4",           # JPEG Extension 4 …
    0xF5:     "JPG5",           # JPEG Extension 5 …
    0xF6:     "JPG6", 	#  JPEG Extension 6 	(Not common)
    0xF7:     "JPG7",   #  SOF48 	JPEG Extension 7, JPEG-LS 	Lossless JPEG
    0xF8:     "JPG8",   #  LSE 	JPEG Extension 8,JPEG-LS Extension 	Lossless JPEG Extension Parameters
    0xF9:     "JPG9", 	# JPEG Extension 9 	(Not common)
    0xFA:     "JPG10", 	# JPEG Extension 10 	(Not common)
    0xFB:     "JPG11", 	# JPEG Extension 11 	(Not common)
    0xFC:     "JPG12", 	# JPEG Extension 12 	(Not common)
    0xFD:     "JPG13", 	# JPEG Extension 13 	(Not common)
    0xFE:     "COM", 	# Comment
}

SEGMENT_KEY_ARR = np.array(list(SEGMENTS.keys()))

@dataclass
class JPEG:
    """ represents jpeg in memory """
    name: str
    data: np.ndarray = field(init=False)

    segments: OrderedDict = field(default_factory=OrderedDict)

    def __post_init__(self):
        self._load_data()
        self._find_segments()

    def _load_data(self):
        """ load data as raw bytes """
        self.data= np.fromfile(self.name, dtype=np.uint8)

    def _find_segments(self):
        """ find and store the index of segments in the jpeg image
        plsplspls work, this took so long to write"""
        maybe_seg = np.where(self.data[:-1] == 0xFF)[0] # check every element but the lase,
        seg_type = self.data[maybe_seg + 1] # add scalar 1 to each
        true_seg = np.isin(seg_type, SEGMENT_KEY_ARR)
        for name, place in zip(seg_type[true_seg], maybe_seg[true_seg]):
            self.segments[SEGMENTS[name]] = place


if __name__ == "__main__":
    import sys
    jpg =JPEG(sys.argv[1])
    print("segments found = ", jpg.segments)
