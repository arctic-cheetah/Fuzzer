# m0wii's inner thoughts

I originally thought cv2 was the answer, but that abstracts away control over metadata

jpegio was made for this
- super annoying to install, needs wheels, might try to compile from source

tried jpeglib, was kinda useless


### what is the jpeg file format
https://docs.fileformat.com/image/jpeg/#file-structure
    something something discrete cosine transform on 8*8 blocks

in bytes (memory): represented by a sequence of segments, each segment begins with a marker

list of all markers: 

okay so ive come to the conclusion that i don't actually need to use the jpeg, so really i can get away with loading the jpeg as an array of bytes into numpy, and then parsing out all the markers
then i can store this num array and where all the markers are, and mutate according to the markers accordingly
useful links:
+ https://www.file-recovery.com/jpg-signature-format.htm
+ https://www.disktuna.com/list-of-jpeg-markers/
+ https://docs.fileformat.com/image/jpeg/

#### Segment fields
i am blind apparently it was on wikipedia https://en.wikipedia.org/wiki/JPEG_File_Interchange_Format [#JFIF APP0 marker segmen]
 blind again, alex's website was wayyy better: https://mykb.cipindanci.com/archive/SuperKB/1294/JPEG%20File%20Layout%20and%20Format.htm

some mutations we could use?
SOF_
* height and width

APP_
* 


## standards:

https://www.w3.org/Graphics/JPEG/jfif3.pdf
an article from ISO
https://www-spiedigitallibrary-org.wwwproxy1.library.unsw.edu.au/journals/journal-of-electronic-imaging/volume-27/issue-04/040901/JPEG-1-standard-25-years--past-present-and-future/10.1117/1.JEI.27.4.040901.full
