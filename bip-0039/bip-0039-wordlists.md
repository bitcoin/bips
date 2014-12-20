#Wordlists

* [English](english.txt)
* [Japanese](japanese.txt)
* [Spanish](spanish.txt)
* [Chinese (Simplified)](chinese_simplified.txt)
* [Chinese (Traditional)](chinese_traditional.txt)

##Wordlists (Special Considerations)

###Japanese

1. **Developers implementing phrase generation or checksum verification must separate words using ideographic spaces / accommodate users inputting ideographic spaces.**  
(UTF-8 bytes: **0xE38080**; C/C+/Java: **"\u3000"**; Python: **u"\u3000"**)  
However, code that only accepts Japanese phrases but does not generate or verify them should be fine as is.
This is because when generating the seed, normalization as per the spec will
automatically change the ideographic spaces into normal ASCII spaces, so as long as your code never shows the user an ASCII space
separated phrase or tries to split the phrase input by the user, dealing with ASCII or Ideographic space is the same.

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
