// Ce script est injecté directement dans toutes les pages web que l'utilisateur visite.
// Contrairement à background.js, il a un accès direct au DOM de la page, donc il peut modifier ce que l'utilisateur voit.

// Écoute les messages provenant de l'extension (par exemple, un message envoyé par notre background.js)
chrome.runtime.onMessage.addListener((msg) => {
  
  // On vérifie si le message reçu est bien l'ordre d'afficher l'avertissement
  if (msg.type === "SHOW_WARNING") {
    
    // Crée un nouvel élément div (boîte HTML) pour notre interface d'alerte
    const overlay = document.createElement("div");

    // Ajoute du style HTML/CSS en ligne pour créer un écran superposé ("overlay")
    // qui couvre toute la fenêtre du navigateur, avec un fond rouge et un texte centré.
    overlay.innerHTML = `
      <div style="
        position:fixed;
        top:0;
        left:0;
        width:100%;
        height:100%;
        background:red;
        z-index:999999; /* Z-index très élevé pour passer par-dessus tous les éléments existants de la page */
        color:white;
        display:flex;
        justify-content:center;
        align-items:center;
        font-size:30px;
        font-weight:bold;
        font-family:sans-serif;
      ">
        ⚠️ Site Dangereux (Bloqué par ShieldGuard)
      </div>
    `;

    // Injecte cet overlay dans la page.
    // On vérifie d'abord si le body existe (au cas où la page charge très lentement), 
    // sinon on l'attache à la racine du document.
    if (document.body) {
      document.body.appendChild(overlay);
    } else {
      document.documentElement.appendChild(overlay);
    }
  }
});
