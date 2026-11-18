const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'techsetup_db'
});

db.connect((err) => {
  if (err) {
    console.error('Erreur MySQL :', err);
    return;
  }
  console.log('Connecté à MySQL avec succès !');
});

// ================= PRODUCT ROUTES =================

// Récupérer les produits
app.get('/api/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

// Ajouter un produit (avec stock)
app.post('/api/products', (req, res) => {
  const { name, category, price, description, image_url, stock } = req.body;
  const productStock = stock || 10;

  const query = 'INSERT INTO products (name, category, price, description, image_url, stock) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(query, [name, category, price, description, image_url, productStock], (err, result) => {
    if (err) return res.status(500).json({ error: "Erreur ajout produit" });
    res.status(201).json({ message: 'Produit ajouté avec succès !', productId: result.insertId });
  });
});

// Modifier un produit
app.put('/api/products/:id', (req, res) => {
  const { id } = req.params;
  const { name, category, price, description, image_url, stock } = req.body;

  const query = 'UPDATE products SET name = ?, category = ?, price = ?, description = ?, image_url = ?, stock = ? WHERE id = ?';
  db.query(query, [name, category, price, description, image_url, stock, id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur modification produit" });
    res.json({ message: 'Produit mis à jour avec succès !' });
  });
});

// Supprimer un produit
app.delete('/api/products/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM products WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur suppression produit" });
    res.json({ message: 'Produit supprimé avec succès !' });
  });
});


// ================= AUTHENTIFICATION & UTILISATEURS =================

// Inscription client
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, "client", "active")';
    db.query(query, [name, email, hashedPassword], (err) => {
      if (err) return res.status(500).json({ error: "Cet email est déjà utilisé." });
      res.status(201).json({ message: 'Compte client créé avec succès !' });
    });
  } catch (error) {
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// Connexion (Vérifie si le compte est bloqué)
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

    const user = results[0];

    // Vérifier si le compte est bloqué
    if (user.status === 'blocked') {
      return res.status(403).json({ error: "Votre compte a été bloqué par l'administrateur." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Email ou mot de passe incorrect." });

    res.json({
      message: 'Connexion réussie',
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  });
});


// ================= ADMIN MANAGEMENT =================

// Lister tous les utilisateurs et compter les clients fidèles
app.get('/api/admin/users', (req, res) => {
  db.query('SELECT id, name, email, role, status, created_at FROM users', (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur." });
    res.json(results);
  });
});

// Modifier le rôle d'un utilisateur
app.put('/api/admin/user-role', (req, res) => {
  const { userId, newRole } = req.body;
  db.query('UPDATE users SET role = ? WHERE id = ?', [newRole, userId], (err) => {
    if (err) return res.status(500).json({ error: "Erreur mise à jour rôle" });
    res.json({ message: "Rôle mis à jour !" });
  });
});

// Bloquer ou Débloquer un compte utilisateur
app.put('/api/admin/user-status', (req, res) => {
  const { userId, newStatus } = req.body;
  db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId], (err) => {
    if (err) return res.status(500).json({ error: "Erreur modification statut" });
    res.json({ message: `Compte ${newStatus === 'blocked' ? 'bloqué' : 'activé'} avec succès !` });
  });
});

// Changer mot de passe admin
app.put('/api/admin/password', async (req, res) => {
  const { userId, oldPassword, newPassword } = req.body;
  db.query('SELECT * FROM users WHERE id = ?', [userId], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé." });

    const user = results[0];
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(401).json({ error: "Ancien mot de passe incorrect." });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], (err) => {
      if (err) return res.status(500).json({ error: "Erreur mise à jour mot de passe." });
      res.json({ message: "Mot de passe mis à jour avec succès !" });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});