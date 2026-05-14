// Ce script tourne en arrière-plan (service worker) et écoute les événements du navigateur de manière invisible.

// Écoute l'événement déclenché JUSTE AVANT que le navigateur ne commence à naviguer vers une nouvelle URL.
chrome.webNavigation.onBeforeNavigate.addListener(
  async (details) => {
    // Si frameId n'est pas 0, cela signifie que c'est une iframe (une page imbriquée dans une page principale). 
    // On l'ignore pour ne vérifier que l'URL principale de l'onglet et éviter les alertes en double.
    if (details.frameId !== 0) return;

    const url = details.url;
    console.log("URL interceptée:", url);

    try {
      // Envoi de l'URL à notre backend local (l'API d'analyse que tu vas créer ensuite)
      const response = await fetch(
        "http://localhost:8765/analyze/url",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url })
        }
      );

      // Récupération de la réponse du backend au format JSON
      const result = await response.json();
      console.log("Résultat du backend:", result);

      // Si le backend indique que l'URL est dangereuse (danger: true)
      if (result.danger) {
        // PROBLÈME CLASSIQUE : Le backend répond si vite que la page n'a pas encore eu le temps
        // d'injecter notre content.js ! Il n'y a donc personne pour écouter le message.
        // SOLUTION : On crée une fonction qui réessaie d'envoyer le message plusieurs fois.
        let tentatives = 10;
        
        const envoyerAlerte = () => {
          chrome.tabs.sendMessage(details.tabId, {
            type: "SHOW_WARNING",
            data: result
          }).catch((erreur) => {
            if (tentatives > 0) {
              tentatives--;
              setTimeout(envoyerAlerte, 200); // On attend 200 millisecondes et on réessaie
            } else {
              console.log("Échec final : le content script n'a jamais répondu.", erreur);
            }
          });
        };
        
        envoyerAlerte(); // On lance la première tentative
      }
    } catch (error) {
      // Gère le cas où le backend n'est pas lancé, injoignable, ou s'il y a une erreur réseau
      console.log("Le backend est hors ligne ou inaccessible.");
    }
  }
);
