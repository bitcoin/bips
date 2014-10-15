#Wordlists

* [English](english.txt)
* [Japanese](japanese.txt)

##Wordlists (Special Considerations)

###Japanese

1. Users will most likely separate the words with UTF-8 ideographic space.  
(UTF-8 bytes: 0xE38080) When generating the seed, normalization as per the spec will
automatically change these into normal ASCII spaces. Depending on the font, displaying the
words should use the UTF-8 ideographic space if it looks like the symbols are too close.

2. Word-wrapping doesn't work well, so making sure that words only word-wrap at one of the  
ideographic spaces may be a necessary step. As a long word split in two could be mistaken easily  
for two smaller words (This would be a problem with any of the 3 character sets in Japanese)
