<!DOCTYPE html>
<html>
<head>
  <title>CTF Network Attack Script</title>
</head>
<body>

<h1 align="center">CTF Network Attack Script</h1>

<p align="center">
  <img src="https://img.shields.io/badge/language-Python-blue">
  <img src="https://img.shields.io/badge/version-1.0-green">
  <img src="https://img.shields.io/badge/status-working-success">
</p>

<h2>📜 Description</h2>

<p>Ce script Python est conçu pour des <strong>tests de sécurité en environnement de CTF</strong> (Capture The Flag). Il exécute diverses attaques réseau, telles que <strong>ARP Spoofing</strong>, <strong>DHCP Starvation</strong>, <strong>serveur DHCP Rogue</strong>, <strong>DNS Spoofing</strong> et <strong>sniffing des identifiants HTTP</strong>. Le script utilise le multithreading pour optimiser la vitesse et les performances, permettant de mener plusieurs attaques simultanément.</p>

<p>⚠️ <strong>Attention : Ce script est strictement réservé à des fins éducatives et de tests de sécurité en environnement autorisé.</strong></p>

<h2>📂 Fonctionnalités</h2>

<ul>
  <li><strong>ARP Spoofing</strong> : Empoisonnement des tables ARP pour rediriger le trafic d'une cible spécifique à travers la machine d'attaque.</li>
  <li><strong>DHCP Starvation</strong> : Épuisement du pool d'adresses IP d'un serveur DHCP légitime.</li>
  <li><strong>Serveur DHCP Rogue</strong> : Attribution de fausses configurations réseau aux clients DHCP.</li>
  <li><strong>DNS Spoofing</strong> : Redirection des requêtes DNS pour des domaines spécifiques vers des IP contrôlées.</li>
  <li><strong>HTTP Sniffing</strong> : Capture des données HTTP POST (par exemple, identifiants de connexion) sur le réseau cible.</li>
</ul>

<h2>📋 Prérequis</h2>

<ul>
  <li>Python 3.x</li>
  <li>Bibliothèque Scapy (<code>pip install scapy</code>)</li>
  <li>Droits administrateur (sudo) pour exécuter certaines attaques réseau</li>
</ul>

<h2>🚀 Installation et Exécution</h2>

<ol>
  <li>Clonez le dépôt :
    <pre><code>git clone https://github.com/votre-utilisateur/ctf-network-attack-script.git
cd ctf-network-attack-script</code></pre>
  </li>
  <li>Installez les dépendances requises :
    <pre><code>pip install -r requirements.txt</code></pre>
  </li>
  <li>Exécutez le script avec les privilèges administrateur :
    <pre><code>sudo python3 network_attack_script.py</code></pre>
  </li>
</ol>

<h2>⚙️ Utilisation</h2>

<p>Le script s'exécute automatiquement en chaîne, exécutant chaque attaque de manière séquentielle. Voici une brève explication de chaque étape :</p>

<ul>
  <li><strong>ARP Spoofing</strong> : Empoisonne la cible et la passerelle pour intercepter le trafic réseau.</li>
  <li><strong>DHCP Starvation</strong> : Envoie plusieurs requêtes DHCP Discover pour épuiser les adresses IP du serveur DHCP légitime.</li>
  <li><strong>Serveur DHCP Rogue</strong> : Répond aux clients DHCP avec de fausses configurations réseau.</li>
  <li><strong>HTTP Sniffing</strong> : Capture et affiche en continu les requêtes HTTP POST.</li>
</ul>

<h2>⚠️ Avertissement</h2>

<p>L'utilisation de ce script en dehors d'un environnement de test autorisé ou d'une compétition CTF peut être illégale et contraire à l'éthique. Assurez-vous d'obtenir l'autorisation de l'administrateur réseau avant d'exécuter ce script sur un réseau réel. L'auteur décline toute responsabilité quant à l'usage inapproprié de ce script.</p>

<hr>

<h2>📧 Contact</h2>

<p>Pour toute question ou suggestion, contactez-nous à <a href="mailto:votre-email@example.com">votre-email@example.com</a>.</p>

</body>
</html>
