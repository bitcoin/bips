#Wordlists

* [English](english.txt)
* [Japanese](japanese.txt)
* [Spanish](spanish.txt)
* [Chinese (Simplified)](chinese_simplified.txt)
* [Chinese (Traditional)](chinese_traditional.txt)

##Wordlists (Special Considerations)

###Japanese

1. Users will most likely separate the words with UTF-8 ideographic space.  
(UTF-8 bytes: 0xE38080) When generating the seed, normalization as per the spec will
automatically change these into normal ASCII spaces. Depending on the font, displaying the
words should use the UTF-8 ideographic space if it looks like the symbols are too close.

2. Word-wrapping doesn't work well, so making sure that words only word-wrap at one of the  
ideographic spaces may be a necessary step. As a long word split in two could be mistaken easily  
for two smaller words (This would be a problem with any of the 3 character sets in Japanese)

###Spanish

1. Words can be uniquely determined typing the first 4 characters (sometimes less).

2. Special Spanish characters like 'ñ', 'ü', 'á', etc... are considered equal to 'n', 'u', 'a', etc... in terms of identifying a word. Therefore, there is no need to use a Spanish keyboard to introduce the passphrase, an application with the Spanish wordlist will be able to identify the words after the first 4 chars have been typed even if the chars with accents have been replaced with the equivalent without accents.

3. There are no words in common between the Spanish wordlist and any other language wordlist, therefore it is possible to detect the language with just one word.

###Chinese

1. Chinese text typically does not use any spaces as word separators. For the sake of
uniformity, we propose to use normal ASCII spaces (0x20) to separate words as per standard.
