# IPK projekt 1

## Zadání
Cílem projektu bylo vytvořit lightweight server s co nejmenším počtem závislostí v jazyce C++. Tento server komunikuje prostřednictvím protokolu HTTP a poskytuje různé informace o systému.

## Spuštění
Nejprve je nutné si rozbalit soubor xkorva03.zip a poté provést překlad zdrojového souboru pomocí příkazu `make`. Tím vznikne spustitelný soubor `hinfosvc`. 
Pro správné spuštění programu je nutné jej spustit následovně: `./hinfosvc [port number]`. Kde port number označuje lokální port na, kterém bude server naslouchat požadavkům.
Číslo portu je omezeno na čísla v rozmezí od 0 do 65 535.
```
$ unzip xkorva03.zip
$ make
$ ./hinfosvc 8000
```

## Použití
Program dokáže poskytnout následující informace:
* Doménové jméno serveru (hostname)
* Jméno procesoru (cpu-name)
* Aktuální zátěž (load)


Pokud by na server byl zaslán nevalidní požadavek server by vrátil odpověd: 400 Bad Request.
Pokud je server spuštěn v daném terminálu a ne na pozadí je možné jej ukončit pomocí `CTRL + C`.

### Příklady spuštění
Server je nutné nejprve spustit `./hinfosvc 8000 &` a poté je možné využít jednu z možností komunikace s tímto servrem.
Jednou z těchto možností je přes webový prohlížeč a nebo pomocí nástrojů curl nebo wget.
```
$ curl http://localhost:8000/hostname
  merlin.fit.vutbr.cz

$ curl http://localhost:8000/cpu-name
  Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz 

$ curl http://localhost:8000/load
  5%
```
Obdobně by bylo možné použít wget jen by se počáteční `curl` nahradilo pomocí `wget`.
Pomocí webového prohlížeče by se komunikovalo následovně: Do prostoru pro adresu by se jednoduše
zadalo: `localhost:8000/load` a v prohližeči by se vypsala aktualní zátěž procesoru. Úplně stejně by
bylo možné vypsat doménové jméno serveru nebo jméno procesoru.<br/>

