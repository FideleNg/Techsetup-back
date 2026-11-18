const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());

// Connexion à la base de données MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Mets ton mot de passe MySQL si tu en as un
  database: 'techsetup_db' // Remplace par le nom de ta base de données
});

db.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données MySQL :', err);
    return;
  }
  console.log('Connecté à la base de données MySQL avec succès !');
});

// ==========================================
// ROUTES PRODUITS
// ==========================================

// Récupérer tous les produits
app.get('/api/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) {
      console.error('Erreur récupération produits :', err);
      return res.status(500).json({ error: "Erreur serveur" });
    }
    res.json(results);
  });
});

// Ajouter un produit (Réservé aux admins dans l'esprit, sécurisable plus tard)
app.post('/api/products', (req, res) => {
  const { name, category, price, description, image_url } = req.body;
  const query = 'INSERT INTO products (name, category, price, description, image_url) VALUES (?, ?, ?, ?, ?)';
  
  db.query(query, [name, category, price, description, image_url], (err, result) => {
    if (err) {
      console.error('Erreur ajout produit :', err);
      return res.status(500).json({ error: "Erreur lors de l'ajout du produit" });
    }
    res.status(201).json({ message: 'Produit ajouté avec succès !', productId: result.insertId });
  });
});


// ==========================================
// ROUTES AUTHENTIFICATION & UTILISATEURS
// ==========================================

// 1. INSCRIPTION : Tous les nouveaux comptes créés via le site ont le rôle 'client' par défaut
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const defaultRole = 'client'; // Rôle forcé à client par sécurité

  try {
    // Hachage sécurisé du mot de passe avec bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    db.query(query, [name, email, hashedPassword, defaultRole], (err, result) => {
      if (err) {
        console.error("Erreur inscription :", err);
        return res.status(500).json({ error: "Cet email est déjà utilisé ou une erreur est survenue." });
      }
      res.status(201).json({ message: 'Compte client créé avec succès !' });
    });
  } catch (error) {
    console.error("Erreur hachage :", error);
    res.status(500).json({ error: "Erreur serveur lors du hachage." });
  }
});

// 2. CONNEXION : Vérifie les identifiants et le hachage du mot de passe
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error("Erreur connexion :", err);
      return res.status(500).json({ error: "Erreur serveur." });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect." });
    }

    const user = results[0];

    // Comparaison du mot de passe saisi avec le hash stocké en base
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect." });
    }

    // Connexion réussie : on renvoie les infos de l'utilisateur (sans le mot de passe)
    res.json({
      message: 'Connexion réussie',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role // 'admin' ou 'client'
      }
    });
  });
});


// ==========================================
// ROUTES DE GESTION ADMINISTRATEUR
// ==========================================

// Lister tous les utilisateurs (pour que l'admin puisse voir les rôles)
app.get('/api/admin/users', (req, res) => {
  db.query('SELECT id, name, email, role, created_at FROM users', (err, results) => {
    if (err) {
      console.error("Erreur lecture utilisateurs :", err);
      return res.status(500).json({ error: "Erreur serveur." });
    }
    res.json(results);
  });
});

// Modifier le rôle d'un utilisateur (Passer un client en admin ou vice-versa)
app.put('/api/admin/user-role', (req, res) => {
  const { userId, newRole } = req.body;

  if (!['client', 'admin'].includes(newRole)) {
    return res.status(400).json({ error: "Rôle invalide." });
  }

  const query = 'UPDATE users SET role = ? WHERE id = ?';
  db.query(query, [newRole, userId], (err) => {
    if (err) {
      console.error("Erreur modification rôle :", err);
      return res.status(500).json({ error: "Erreur lors de la mise à jour du rôle." });
    }
    res.json({ message: "Rôle mis à jour avec succès !" });
  });
});

// Modifier le mot de passe administrateur
app.put('/api/admin/password', async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;

  db.query('SELECT * FROM users WHERE id = ?', [userId], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: "Utilisateur non trouvé." });
    }

    const user = results[0];
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.status(401).json({ error: "Ancien mot de passe incorrect." });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], (err) => {
      if (err) {
        return res.status(500).json({ error: "Erreur lors de la mise à jour du mot de passe." });
      }
      res.json({ message: "Mot de passe administrateur mis à jour avec succès !" });
    });
  });
});

// Lancement du serveur
app.listen(PORT, () => {
  console.log(`Serveur Node.js démarré sur le port ${PORT}`);
});