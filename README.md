# English version

This project converts TZSP packets into a virtual network interface, allowing live traffic analysis with any network monitoring or packet analysis tool.

## Project structure

- `tzsp2pcap_live.c` — Main source (do not edit directly)
- `Makefile` — For quick compilation (`make`)
- `default.nix` and `nix/package.nix` — For reproducible builds with Nix

## Build

### Method 1: Makefile
```sh
make
```

### Method 2: Nix
```sh
nix-build
```

## Run

Launch the program (you may need root privileges):
```sh
./tzsp2pcap_live
```

## Usage

1. Make sure the `tzsp0` interface is created and receiving traffic.
2. Configure your traffic analysis tool (e.g. tcpdump, Zeek, Wireshark, etc.) to listen on `tzsp0`.
3. Start your preferred tool, for example:
   ```sh
   tcpdump -i tzsp0
   # or
   wireshark -i tzsp0
   # or
   zeek -i tzsp0
   ```

---
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

   # tzsp2pcap

   ## English

   This project converts TZSP packets into a local virtual network interface, enabling live traffic analysis with any network monitoring or packet analysis tool.

   ### Project structure

   - `tzsp2pcap_live.c` — Main source (do not edit directly)
   - `Makefile` — For quick compilation (`make`)
   - `default.nix` and `nix/package.nix` — For reproducible builds with Nix

   ### Build

   **Method 1: Makefile**
   ```sh
   make
   ```

   **Method 2: Nix**
   ```sh
   nix-build
   ```

   ### Run

   Launch the program (you may need root privileges):
   ```sh
   ./tzsp2pcap_live
   ```

   ### Usage

   1. Ensure the `tzsp0` interface is created and receiving traffic.
   2. Configure your analysis tool (e.g. Suricata, Zeek, tcpdump, Wireshark, etc.) to listen on `tzsp0`.
   3. Start your preferred tool, for example:
      ```sh
      tcpdump -i tzsp0
      # or
      wireshark -i tzsp0
      # or
      suricata -c /etc/suricata/suricata.yaml -i tzsp0
      ```

   ### Notes
   - Do not edit `tzsp2pcap_live.c` directly.
   - If using Suricata, update rules with `suricata-update` or download them manually.

   ### License
   BSD or as specified in the sources.

   ---

   ## Italiano

   Questo progetto converte pacchetti TZSP in un'interfaccia di rete virtuale locale, permettendo l'analisi live del traffico con qualsiasi strumento di network monitoring o packet analysis.

   ### Struttura del progetto

   - `tzsp2pcap_live.c` — Sorgente principale (non modificare direttamente)
   - `Makefile` — Per la compilazione rapida (`make`)
   - `default.nix` e `nix/package.nix` — Per build riproducibili con Nix

   ### Compilazione

   **Metodo 1: Makefile**
   ```sh
   make
   ```

   **Metodo 2: Nix**
   ```sh
   nix-build
   ```

   ### Esecuzione

   Lancia il programma (potresti aver bisogno dei permessi di root):
   ```sh
   ./tzsp2pcap_live
   ```

   ### Utilizzo

   1. Assicurati che l'interfaccia `tzsp0` sia creata e riceva traffico.
   2. Configura il tuo strumento di analisi del traffico (es. Suricata, Zeek, tcpdump, Wireshark, ecc.) per ascoltare su `tzsp0`.
   3. Avvia lo strumento desiderato, ad esempio:
      ```sh
      tcpdump -i tzsp0
      # oppure
      wireshark -i tzsp0
      # oppure
      suricata -c /etc/suricata/suricata.yaml -i tzsp0
      ```

   ### Note
   - Non modificare direttamente `tzsp2pcap_live.c`.
   - Se usi Suricata, per aggiornare le regole puoi usare `suricata-update` o scaricarle manualmente.

   ### Licenza
   BSD o come specificato nei sorgenti.
