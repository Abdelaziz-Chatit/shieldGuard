from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# Configuration du CORS (Cross-Origin Resource Sharing)
# Très important : cela autorise l'extension Chrome à envoyer des requêtes à ce backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Autorise toutes les origines
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modèle de données pour valider ce qu'on reçoit de l'extension
class URLRequest(BaseModel):
    url: str

# C'est l'URL que l'extension appelle en POST (http://localhost:8765/analyze/url)
@app.post("/analyze/url")
async def analyze_url(request: URLRequest):
    print(f"🕵️‍♂️ Analyse de l'URL : {request.url}")
    
    # --- LOGIQUE DE DÉTECTION (Basique pour le moment) ---
    is_dangerous = False
    
    # Exemple de règle : Si l'URL contient "paypal" et "free", c'est louche !
    url_lower = request.url.lower()
    if "paypal" in url_lower and "free" in url_lower:
        is_dangerous = True
        print("🚨 DANGER DÉTECTÉ !")
    else:
        print("✅ URL Saine.")
        
    # On renvoie le résultat au format JSON attendu par l'extension
    return {"danger": is_dangerous}

if __name__ == "__main__":
    print("🚀 Démarrage du serveur ShieldGuard sur http://localhost:8765")
    # Lance le serveur local sur le port 8765
    uvicorn.run(app, host="localhost", port=8765)
