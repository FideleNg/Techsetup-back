// 1. Importation des modules nécessaires
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

// 2. Initialisation de l'application Express
const app = express();
const PORT = 5000; // Le port sur lequel notre serveur va écouter

// 3. Application des sécurités et middlewares
app.use(cors()); // Autorise les requêtes venant d'autres origines (notamment React)
app.use(express.json()); // Permet au serveur de comprendre les données envoyées au format JSON

// 4. Connexion sécurisée à la base de données MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',      
    password: '',  
    database: 'techsetup_db'
});

db.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données : ' + err.stack);
        return;
    }
    console.log('Connecté à la base de données MySQL avec succès ');
});

// 5. Création d'une route API pour récupérer les produits
// Quand quelqu'un va sur http://localhost:5000/api/products, le serveur exécute ceci :
app.get('/api/products', (req, res) => {
    const query = 'SELECT * FROM products';
    
    // Requête sécurisée vers MySQL
    db.query(query, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Erreur serveur lors de la récupération des produits' });
        }
        // On renvoie les produits sous format JSON au Front-end
        res.json(results);
    });
});

// 6. Démarrage du serveur
app.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT} `);
});