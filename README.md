<h1 align="center"> Projet Burglar </h1>

## 📜 Description

Ce script exécute diverses attaques réseau, telles que **ARP Spoofing**, **DHCP Starvation**, **serveur DHCP Rogue**, **DNS Spoofing** et **sniffing des identifiants HTTP**. Le script utilise le multithreading pour optimiser la vitesse et les performances, permettant de mener plusieurs attaques simultanément.

⚠️ **Attention : Ce script est strictement réservé à des fins éducatives et de tests de sécurité en environnement autorisé.**

## 📂 Fonctionnalités

- **ARP Spoofing** : Empoisonnement des tables ARP pour rediriger le trafic d'une cible spécifique à travers la machine d'attaque.
- **DHCP Starvation** : Épuisement du pool d'adresses IP d'un serveur DHCP légitime.
- **Serveur DHCP Rogue** : Attribution de fausses configurations réseau aux clients DHCP.
- **DNS Spoofing** : Redirection des requêtes DNS pour des domaines spécifiques vers des IP contrôlées.
- **HTTP Sniffing** : Capture des données HTTP POST (par exemple, identifiants de connexion) sur le réseau cible.

## 📋 Prérequis

- Python 3.x
- Bibliothèque Scapy (`pip install scapy`)
- Droits administrateur (sudo) pour exécuter certaines attaques réseau

## 🚀 Installation et Exécution

1. Clonez le dépôt :

   ```bash
   git clone (https://github.com/SkyM1raj/Burglar)
   cd Burglar
   ```
2. Installez les dépendances requises :

   ```bash
   pip install -r requirements.txt
   ```

Exécutez le script avec les privilèges administrateur :

   ```bash
   sudo python3 burglar.py
   ```
## ⚙️ Utilisation

Le script s'exécute automatiquement en chaîne, exécutant chaque attaque de manière séquentielle. Voici une brève explication de chaque étape :

- **ARP Spoofing** : Empoisonne la cible et la passerelle pour intercepter le trafic réseau.
- **DHCP Starvation** : Envoie plusieurs requêtes DHCP Discover pour épuiser les adresses IP du serveur DHCP légitime.
- **Serveur DHCP Rogue** : Répond aux clients DHCP avec de fausses configurations réseau.
- **HTTP Sniffing** : Capture et affiche en continu les requêtes HTTP POST.

## ⚠️ Avertissement

L'utilisation de ce script en dehors d'un environnement de test autorisé ou d'une compétition CTF peut être illégale et contraire à l'éthique. Assurez-vous d'obtenir l'autorisation de l'administrateur réseau avant d'exécuter ce script sur un réseau réel. L'auteur décline toute responsabilité quant à l'usage inapproprié de ce script.
