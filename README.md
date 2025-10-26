# tzsp2pcap

Questo progetto converte pacchetti TZSP in un'interfaccia di rete virtuale, permettendo l'analisi live del traffico tramite strumenti di network monitoring e packet analysis.

## Struttura del progetto

- `tzsp2pcap_live.c` 
- `Makefile` — Per la compilazione rapida (`make`)
- `default.nix` e `nix/package.nix` — Per build riproducibili con Nix

## Compilazione

### Metodo 1: Makefile
```sh
make
```

### Metodo 2: Nix
```sh
nix-build
```

## Esecuzione

Lancia il programma (potresti aver bisogno dei permessi di root):
```sh
./tzsp2pcap_live
```


## Utilizzo

1. Assicurati che l'interfaccia `tzsp0` sia creata e riceva traffico.
2. Configura il tuo strumento di analisi del traffico (es. tcpdump, Zeek, Wireshark, ecc.) per ascoltare su `tzsp0`.
3. Avvia lo strumento desiderato, ad esempio:
   ```sh
   tcpdump -i tzsp0
   # oppure
   wireshark -i tzsp0
   # oppure
   suricata -c /etc/suricata/suricata.yaml -i tzsp0
   ```
