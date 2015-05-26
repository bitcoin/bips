#Wordlists

* [English](english.txt)
* [Japanese](japanese.txt)
* [Spanish](spanish.txt)
* [Chinese (Simplified)](chinese_simplified.txt)
* [Chinese (Traditional)](chinese_traditional.txt)
* [French](french.txt)

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

###French

Credits: @Kirvx @NicolasDorier @ecdsa @EricLarch
([The pull request](https://github.com/bitcoin/bips/issues/152))

1.  High priority on simple and common french words.
2.  Only words with 5-8 letters.
3.  A word is fully recognizable by typing the first 4 letters (special french characters "é-è" are considered equal to "e", for exemple "museau" and "musée" can not be together).
4.  Only infinitive verbs, adjectives and nouns.
5.  No pronouns, no adverbs, no prepositions, no conjunctions, no interjections (unless a noun/adjective is also popular than its interjection like "mince;chouette").
6.  No numeral adjectives.
7.  No words in the plural (except invariable words like "univers", or same spelling than singular like "heureux").
8.  No female adjectives (except words with same spelling for male and female adjectives like "magique").
9.  No words with several senses AND different spelling in speaking like "verre-vert", unless a word has a meaning much more popular than another like "perle" and "pairle".
10. No very similar words with 1 letter of difference.
11. No essentially reflexive verbs (unless a verb is also a noun like "souvenir").
12. No words with "ô;â;ç;ê;œ;æ;î;ï;û;ù;à;ë;ÿ".
13. No words ending by "é;ée;è;et;ai;ait".
14. No demonyms.
15. No words in conflict with the spelling corrections of 1990 (http://goo.gl/Y8DU4z).
16. No embarrassing words (in a very, very large scope) or belonging to a particular religion.
17. No identical words with the Spanish wordlist (as Y75QMO wants).
