#Wordlists

* [English](bip-0039/english.txt)
* [Japanese](bip-0039/japanese.txt)

##Wordlists (Special Considerations)

###Japanese

1. Users will most likely separate the words with UTF-8 ideographic space.  
(UTF-8 bytes: 0xE38080) When splitting for validation or joining for generation, replace  
all instances of ascii space with the ideographic space, and in case of a mixture of space  
types, also replace just before seed generation.

2. Word-wrapping doesn't work well, so making sure that words only word-wrap at one of the  
ideographic spaces may be a necessary step. As a long word split in two could be mistaken easily  
for two smaller words (This would be a problem with any of the 3 character sets in Japanese)