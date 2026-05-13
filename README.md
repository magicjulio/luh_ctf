# 2tes treffen plan

Ich hab von vielen von euch gehört das es letzes mal etwas zu schnell ging. Deswegen möchte ich dieses mal etwas langsamer dran gehen


# First: a real 0 Day. You can try it.

you need: ssh
** ssh luhi@ip **

flag: (sudo only) root/flag.txt



## Heutiger CTF

#### Hack the Box
- https://ctf.hackthebox.com/event/1434
- Wir fokussieren uns auf web. Aber ihr könnt gerne auch andere Kategorien probieren.


# 1 Web > Jailbreak
- Tipp 1: lies dir die beschreibung gut durch. Auf welchen teil der website solltest du dich fokussieren?
- Tipp 2: Google: XML External Entity (XXE)
- Tipp 3: Frag dich: welchen teil vom xml wird mir angezeigt nachdem ich es abgeschickt habe?

# 2 Web > TimeKORP
- Tipp 1: Downloade den Source code und öffne ihn in Code. Entferne teile die offensichtlich nicht relevant sind wie assets.
- Tipp 2: Lass dich nicht davon abschreken das du php möglicherweise nicht kennst. Viel ist ähnlich wie zb in java. (e.g consturctor & this)
- Tipp 3: Dein ziel ist es auf dem Zielcomputer linux befehle ausführen zu können. Die flag ist in einer datei "flag". Um sie zu lesen müsstest du cat flag ausführen
- Tipp 4: In TimeModel.php in Z. 11 wird mit exec der linux befehl **date** ausgeführt. Dabei wird ein format angegeben was **du** in Z.6 beeinflussen!
- Tipp 5: Dein input ist $format in: **$this->command = "date '+" . $format . "' 2>&1";** beachte das dein input inerhalb einer string ' ... ' gesetzt wird. Du mustt dieser string _escapen_.
- Tipp 6: Dein command sollte mit ; enden und damit du keine syntax fehler verursachtst kannst du ein kommentar symbol verwenden (#) um den rest der zeile nach deinem input nicht auszuführen.
- Tipp 7: Das dein command immernoch nicht ausgeführt wird kann an der art und weise wie web request verarbeitet werden liegen. Suche online nach einem **url encoder**.

## Auch Interessant: OSINT
- https://ctf.osint.industries/challenges
