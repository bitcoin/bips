# Wordlists

* [English](english.txt)
* [Japanese](japanese.txt)
* [Korean](korean.txt)
* [Spanish](spanish.txt)
* [Chinese (Simplified)](chinese_simplified.txt)
* [Chinese (Traditional)](chinese_traditional.txt)
* [French](french.txt)
* [Italian](italian.txt)
* [Czech](czech.txt)
* [Portuguese](portuguese.txt)

## Wordlists (Special Considerations)

### Japanese

1. **Developers implementing phrase generation or checksum verification must separate words using ideographic spaces / accommodate users inputting ideographic spaces.**
(UTF-8 bytes: **0xE38080**; C/C+/Java: **"\u3000"**; Python: **u"\u3000"**)
However, code that only accepts Japanese phrases but does not generate or verify them should be fine as is.
This is because when generating the seed, normalization as per the spec will
automatically change the ideographic spaces into normal ASCII spaces, so as long as your code never shows the user an ASCII space
separated phrase or tries to split the phrase input by the user, dealing with ASCII or Ideographic space is the same.

2. Word-wrapping doesn't work well, so making sure that words only word-wrap at one of the
ideographic spaces may be a necessary step. As a long word split in two could be mistaken easily
for two smaller words (This would be a problem with any of the 3 character sets in Japanese)

### Spanish

1. Words can be uniquely determined by typing the first 4 characters (sometimes less).

2. Special Spanish characters like 'ñ', 'ü', 'á', etc... are considered equal to 'n', 'u', 'a', etc... in terms of identifying a word. Therefore, there is no need to use a Spanish keyboard to introduce the passphrase, an application with the Spanish wordlist will be able to identify the words after the first 4 chars have been typed even if the chars with accents have been replaced with the equivalent without accents.

3. There are no words in common between the Spanish wordlist and any other language wordlist, therefore it is possible to detect the language with just one word.

### Chinese

1. Chinese text typically does not use any spaces as word separators. For the sake of
uniformity, we propose to use normal ASCII spaces (0x20) to separate words as per standard.

### French

Credits: @Kirvx @NicolasDorier @ecdsa @EricLarch
([The pull request](https://github.com/bitcoin/bips/issues/152))

1.  High priority on simple and common French words.
2.  Only words with 5-8 letters.
3.  A word is fully recognizable by typing the first 4 letters (special French characters "é-è" are considered equal to "e", for example "museau" and "musée" can not be together).
4.  Only infinitive verbs, adjectives and nouns.
5.  No pronouns, no adverbs, no prepositions, no conjunctions, no interjections (unless a noun/adjective is also popular than its interjection like "mince;chouette").
6.  No numeral adjectives.
7.  No words in the plural (except invariable words like "univers", or same spelling as singular like "heureux").
8.  No female adjectives (except words with same spelling for male and female adjectives like "magique").
9.  No words with several senses AND different spelling in speaking like "verre-vert", unless a word has a meaning much more popular than another like "perle" and "pairle".
10. No very similar words with only 1 letter of difference.
11. No essentially reflexive verbs (unless a verb is also a noun like "souvenir").
12. No words with "ô;â;ç;ê;œ;æ;î;ï;û;ù;à;ë;ÿ".
13. No words ending by "é;ée;è;et;ai;ait".
14. No demonyms.
15. No words in conflict with the spelling corrections of 1990 (http://goo.gl/Y8DU4z).
16. No embarrassing words (in a very, very large scope) or belonging to a particular religion.
17. No identical words with the Spanish wordlist (as Y75QMO wants).

### Italian

Credits: @paoloaga @Polve

Words chosen using the following rules:

1. Simple and common Italian words.
2. Length between 4 and 8 characters.
3. First 4 letters must be unique between all words.
4. No accents or special characters.
5. No complex verb forms.
6. No plural words.
7. No words that remind negative/sad/bad things.
8. If both female/male words are available, choose male version.
9. No words with double vowels (like: lineetta).
10. No words already used in other language mnemonic sets.
11. If 3 of the first 4 letters are already used in the same sequence in another mnemonic word, there must be at least other 3 different letters.
12. If 3 of the first 4 letters are already used in the same sequence in another mnemonic word, there must not be the same sequence of 3 or more letters.

Rules 11 and 12 prevent the selection words that are not different enough. This makes each word more recognizable among others and less error prone. For example: the wordlist contains "atono", then "atomo" is rejected, but "atomico" is good.

All the words have been manually selected and automatically checked against the rules.

### Czech

Credits: @zizelevak (Jan Lansky zizelevak@gmail.com)

Words chosen using the following rules:

1.  Words are 4-8 letters long.
2.  Words can be uniquely determined by typing the first 4 letters.
3.  Only words containing all letters without diacritical marks. (It was the hardest task, because one third of all Czech letters has diacritical marks.)
4.  Only nouns, verbs and adverbs, no other word types. All words are in basic form.
5.  No personal names or geographical names.
6.  No very similar words with 1 letter of difference.
7.  Words are sorted according to English alphabet (Czech sorting has difference in "ch").
8.  No words already used in other language mnemonic sets (english, italian, french, spanish). Letters with diacritical marks from these sets are counted as analogous letters without diacritical marks.

### Portuguese

Credits: @alegotardo @bitmover-studio @brenorb @kuthullu @ninjastic @sabotag3x @Trimegistus

1. Words can be uniquely determined by typing the first 4 characters.
2. No accents or special characters.
3. No complex verb forms.
4. No plural words, unless there's no singular form.
5. No words with double spelling.
6. No words with the exact sound as another word with different spelling.
7. No offensive words.
8. No words already used in other language mnemonic sets.
9. The words which have not the same spelling in Brazil and in Portugal are excluded.
10. No words that remind one of negative/sad/bad things.
11. No very similar words with only 1 letter of difference.

### Emoji

Credits: @EmojiSeedDevTeam @ovrdos @CoperbyteLLC 

The **Emoji wordlist** is a deterministic mapping of the 2048 English BIP39 words into **2048 unique emoji pairs**. This allows mnemonic phrases to be displayed and remembered visually, across languages and literacy barriers.

**Rules for Emoji Mapping:**

1. **Direct Match Rule**  
   If a word has a clear, universal emoji (e.g., `dog → 🐶`), the same emoji is used twice:  
   `dog → 🐶, 🐶`.

2. **Seasonal/Calendar Words**  
   Months map to seasonal or holiday emojis:  
   - `october → 🎃, 🎃`  
   - `november → 🦃, 🍂`  
   Days of the week map to calendar/time or celebration emojis:  
   - `friday → 🎉, 🎉`  
   - `sunday → ☀️, ☀️`.

3. **Numbers**  
   Use keycap emojis or `💯` for “hundred”:  
   - `one → 1️⃣, 1️⃣`  
   - `ten → 🔟, 🔟`  
   - `hundred → 💯, 💯`.

4. **Abstract Words**  
   For vague concepts, combine a **primary metaphor** and a **clarifier**:  
   - `ability → 🧠, 💪`  
   - `process → ⚙️, 📊`.

5. **Action Words**  
   For verbs and participles:  
   - `running → 🏃, 💨`  
   - `locked → 🔒, 🔑`.

6. **Clarifier Pools**  
   Second emojis are drawn from predefined sets:  
   - **Action clarifiers**: 🏃, ⚙️, ✍️, 🎯, 💬  
   - **Object clarifiers**: 📦, 📚, 🧩, 📐  
   - **Time clarifiers**: ⏰, 📅, 🌙  
   - **Nature clarifiers**: 🌱, 🔥, 🌊  
   - **Place clarifiers**: 🏠, 🏛️, 🏞️.

7. **Object vs Action Split**  
   - Nouns: `object → object + clarifier`.  
   - Verbs: `action → action + clarifier`.

8. **Tightening Rules**  
   - Duplicate emojis for strong one-to-one matches.  
   - Add clarifiers for ambiguous terms.  
   - Universal fallback: ✅ plus clarifier.

9. **Global Duplicate Check**  
   - All 2048 pairs must be unique.  
   - If a collision occurs, rotate clarifier, then primary, finally fall back to `✅`.

10. **Stability**  
    - Only use **stable Unicode code points**.  
    - No variation selectors or platform-specific glyphs.  
    - Graphemes follow [Unicode TR51](https://unicode.org/reports/tr51/).




