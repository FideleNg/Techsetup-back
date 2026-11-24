import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'techsetup_db',
  waitForConnections: true,
  connectionLimit: 10
});

// --- Configuration Super Admin via variables d'environnement uniquement (aucun secret en dur) ---
const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL
  ? String(process.env.SUPER_ADMIN_EMAIL).trim().toLowerCase()
  : '';
const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD || '';
const SUPER_ADMIN_NAME = process.env.SUPER_ADMIN_NAME || 'Super Admin TechSetup';

const DEFAULT_ADMIN_PERMISSIONS = {
  can_manage_products: false,
  can_manage_orders: true,
  can_manage_cashier: false,
  can_manage_clients: false
};

const EMPTY_PERMISSIONS = {
  can_manage_products: false,
  can_manage_orders: false,
  can_manage_cashier: false,
  can_manage_clients: false
};

const SUPER_ADMIN_PERMISSIONS = {
  can_manage_products: true,
  can_manage_orders: true,
  can_manage_cashier: true,
  can_manage_clients: true
};

// --- Initialisation optionnelle du Super Admin uniquement si les variables d'environnement sont définies ---
async function ensureDatabaseSetup() {
  if (!SUPER_ADMIN_EMAIL || !SUPER_ADMIN_PASSWORD) {
    return;
  }

  try {
    const [existing] = await pool.query(
      'SELECT id, role FROM users WHERE LOWER(TRIM(email)) = ? LIMIT 1',
      [SUPER_ADMIN_EMAIL]
    );
    const hashed = await bcrypt.hash(SUPER_ADMIN_PASSWORD, 12);

    if (!existing[0]) {
      await pool.query(
        `INSERT INTO users (name, email, password_hash, role, status, permissions)
         VALUES (?, ?, ?, 'super_admin', 'active', ?)`,
        [
          SUPER_ADMIN_NAME,
          SUPER_ADMIN_EMAIL,
          hashed,
          JSON.stringify(SUPER_ADMIN_PERMISSIONS)
        ]
      );
      console.log(`Compte Super Admin initialisé depuis l'environnement : ${SUPER_ADMIN_EMAIL}`);
    } else {
      await pool.query(
        `UPDATE users
         SET name = ?, password_hash = ?, role = 'super_admin', status = 'active', permissions = ?
         WHERE id = ?`,
        [
          SUPER_ADMIN_NAME,
          hashed,
          JSON.stringify(SUPER_ADMIN_PERMISSIONS),
          existing[0].id
        ]
      );
    }
  } catch (err) {
    console.error('Info init DB (vérifiez que techsetup_db est importée) :', err.message);
  }
}

function parsePermissions(rawPermissions, role) {
  if (role === 'super_admin') {
    return { ...SUPER_ADMIN_PERMISSIONS };
  }
  if (role !== 'admin') {
    return { ...EMPTY_PERMISSIONS };
  }

  let parsed = {};
  if (typeof rawPermissions === 'string') {
    try {
      parsed = JSON.parse(rawPermissions || '{}');
    } catch {
      parsed = {};
    }
  } else if (rawPermissions && typeof rawPermissions === 'object') {
    parsed = rawPermissions;
  }

  return {
    ...DEFAULT_ADMIN_PERMISSIONS,
    can_manage_products: Boolean(
      parsed.can_manage_products ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_products
    ),
    can_manage_orders: Boolean(
      parsed.can_manage_orders ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_orders
    ),
    can_manage_cashier: Boolean(
      parsed.can_manage_cashier ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_cashier
    ),
    can_manage_clients: Boolean(
      parsed.can_manage_clients ?? DEFAULT_ADMIN_PERMISSIONS.can_manage_clients
    )
  };
}

function sanitizeUser(userRow) {
  if (!userRow) return null;
  const { password_hash, password, ...safeUser } = userRow;
  return {
    ...safeUser,
    permissions: parsePermissions(userRow.permissions, userRow.role)
  };
}

// Prix affiché au client = prix de base + frais de livraison (pour le matériel physique)
// Le client ne voit pas la décomposition des frais de livraison
function formatProductForClient(row) {
  const basePrice = Number(row.price || 0);
  const fee = row.product_type === 'physical' ? Number(row.delivery_fee || 0) : 0;
  const publicPrice = Number((basePrice + fee).toFixed(2));
  return {
    id: row.id,
    product_type: row.product_type,
    name: row.name,
    category: row.category,
    price: publicPrice,
    description: row.description,
    image_url: row.image_url,
    stock: Number(row.stock || 0),
    is_active: row.is_active
  };
}

function formatProductForAdmin(row) {
  const basePrice = Number(row.price || 0);
  const fee = row.product_type === 'physical' ? Number(row.delivery_fee || 0) : 0;
  return {
    ...row,
    base_price: basePrice,
    delivery_fee: fee,
    price: Number((basePrice + fee).toFixed(2))
  };
}

async function verifyPassword(plainPassword, storedPassword) {
  if (!plainPassword || !storedPassword) return false;
  if (String(storedPassword).startsWith('$2')) {
    return bcrypt.compare(String(plainPassword), String(storedPassword));
  }
  return false;
}

// --- Journalisation des activités & trafics ---
async function logActivity({
  actorId = null,
  actorName = 'Système',
  actorRole = 'system',
  module = 'system',
  actionType,
  referenceId = null,
  amount = null,
  details = null,
  conn = pool
}) {
  try {
    await conn.query(
      `INSERT INTO activity_logs
        (actor_id, actor_name, actor_role, module, action_type, reference_id, amount, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        actorId,
        actorName,
        actorRole,
        module,
        actionType,
        referenceId ? String(referenceId) : null,
        amount !== null && amount !== undefined ? Number(amount) : null,
        details
      ]
    );
  } catch (err) {
    console.error('Erreur logActivity :', err.message);
  }
}

// --- Helpers SQL MySQL ---
async function findUserById(userId) {
  const [rows] = await pool.query(
    `SELECT id, name, email, password_hash, phone, role, status, total_orders, permissions
     FROM users
     WHERE id = ?
     LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
}

async function findUserByEmail(email) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const [rows] = await pool.query(
    `SELECT id, name, email, password_hash, phone, role, status, total_orders, permissions
     FROM users
     WHERE LOWER(TRIM(email)) = ?
     LIMIT 1`,
    [normalizedEmail]
  );
  return rows[0] || null;
}

async function updateUserRoleAndPermissions(targetUserId, newRole, permissionsObj) {
  await pool.query(
    `UPDATE users
     SET role = ?,
         permissions = ?
     WHERE id = ?`,
    [newRole, JSON.stringify(permissionsObj), targetUserId]
  );
  return findUserById(targetUserId);
}

async function updateUserPermissionsOnly(targetUserId, permissionsObj) {
  await pool.query(
    `UPDATE users
     SET permissions = ?
     WHERE id = ?`,
    [JSON.stringify(permissionsObj), targetUserId]
  );
  return findUserById(targetUserId);
}

async function attachItemsToOrders(ordersRows) {
  if (!ordersRows.length) return [];
  const orderIds = ordersRows.map((o) => o.id);
  const [itemsRows] = await pool.query(
    `SELECT * FROM order_items WHERE order_id IN (?) ORDER BY id ASC`,
    [orderIds]
  );
  const itemsByOrder = {};
  for (const item of itemsRows) {
    if (!itemsByOrder[item.order_id]) itemsByOrder[item.order_id] = [];
    itemsByOrder[item.order_id].push(item);
  }
  return ordersRows.map((ord) => ({
    ...ord,
    items: itemsByOrder[ord.id] || []
  }));
}

// --- Middlewares d'authentification et de permissions ---
async function attachUser(req, res, next) {
  try {
    const userId = req.header('x-user-id');
    if (!userId) {
      return res.status(401).json({
        error: 'Authentification requise (en-tête x-user-id manquant).'
      });
    }

    const user = await findUserById(userId);
    if (!user) {
      return res.status(401).json({ error: 'Utilisateur introuvable.' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({
        error: 'Compte bloqué.',
        support: 'Contactez le support ou le Super Administrateur.'
      });
    }

    req.currentUser = sanitizeUser(user);
    next();
  } catch (err) {
    console.error('Erreur attachUser :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la vérification de session.' });
  }
}

function requireSuperAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== 'super_admin') {
    return res.status(403).json({
      error: 'Accès refusé : action réservée exclusivement au Super Admin.'
    });
  }
  next();
}

function requireDeliveryOrAdmin(req, res, next) {
  const user = req.currentUser;
  if (!user) return res.status(401).json({ error: 'Non authentifié.' });
  if (
    user.role === 'delivery' ||
    user.role === 'super_admin' ||
    (user.role === 'admin' && Boolean(user.permissions?.can_manage_orders))
  ) {
    return next();
  }
  return res.status(403).json({
    error: 'Accès refusé : réservé aux livreurs et administrateurs des commandes.'
  });
}

function requirePermission(permKey) {
  return (req, res, next) => {
    const user = req.currentUser;
    if (!user) {
      return res.status(401).json({ error: 'Non authentifié.' });
    }
    if (user.role === 'super_admin') {
      return next();
    }
    if (user.role === 'admin' && Boolean(user.permissions?.[permKey])) {
      return next();
    }
    return res.status(403).json({
      error: `Accès refusé : permission "${permKey}" requise.`
    });
  };
}

// --- Authentification & gestion des mots de passe ---
app.post('/api/register', async (req, res) => {
  try {
    const cleanName = String(req.body?.name || '').trim();
    const cleanEmail = String(req.body?.email || '').trim().toLowerCase();
    const cleanPhone = String(req.body?.phone || '').trim() || null;
    const rawPassword = String(req.body?.password || '');

    if (!cleanName || !cleanEmail || rawPassword.length < 8) {
      return res.status(400).json({
        error: 'Nom, email et mot de passe (8 caractères minimum) sont requis.'
      });
    }

    const existing = await findUserByEmail(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé.' });
    }

    const hashedPassword = await bcrypt.hash(rawPassword, 12);

    const [result] = await pool.query(
      `INSERT INTO users (name, email, password_hash, phone, role, status, permissions)
       VALUES (?, ?, ?, ?, 'client', 'active', ?)`,
      [cleanName, cleanEmail, hashedPassword, cleanPhone, JSON.stringify(EMPTY_PERMISSIONS)]
    );

    await logActivity({
      actorId: result.insertId,
      actorName: cleanName,
      actorRole: 'client',
      module: 'auth',
      actionType: 'USER_REGISTERED',
      referenceId: result.insertId,
      details: `Nouveau compte client créé (${cleanEmail})`
    });

    return res.status(201).json({ message: 'Compte créé avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/register :', err);
    res.status(500).json({ error: "Erreur serveur lors de l'inscription." });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const emailInput = String(req.body?.email || '').trim().toLowerCase();
    const passwordInput = String(req.body?.password || '');

    const user = await findUserByEmail(emailInput);
    const isPasswordValid = user
      ? await verifyPassword(passwordInput, user.password_hash)
      : false;

    if (!user || !isPasswordValid) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    if (user.status === 'blocked') {
      return res.status(403).json({
        error: 'Votre compte est bloqué.',
        support: 'Veuillez contacter le support ou le Super Administrateur pour réactiver votre accès.'
      });
    }

    await logActivity({
      actorId: user.id,
      actorName: user.name,
      actorRole: user.role,
      module: 'auth',
      actionType: 'USER_LOGIN',
      referenceId: user.id,
      details: `Connexion réussie (${user.role})`
    });

    return res.json({
      user: sanitizeUser(user)
    });
  } catch (err) {
    console.error('Erreur POST /api/login :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const emailInput = String(req.body?.email || '').trim().toLowerCase();
    const newPassword = String(req.body?.newPassword || '');

    if (!emailInput || newPassword.length < 8) {
      return res.status(400).json({
        error: 'Email requis et nouveau mot de passe (8 caractères minimum).'
      });
    }

    const user = await findUserByEmail(emailInput);
    if (!user) {
      return res.status(404).json({ error: 'Aucun compte associé à cet email.' });
    }

    if (user.role === 'super_admin') {
      return res.status(403).json({
        error: 'La réinitialisation directe du Super Admin est protégée.'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, user.id]);

    await logActivity({
      actorId: user.id,
      actorName: user.name,
      actorRole: user.role,
      module: 'auth',
      actionType: 'PASSWORD_RESET',
      referenceId: user.id,
      details: 'Réinitialisation du mot de passe'
    });

    return res.json({ message: 'Mot de passe réinitialisé avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/forgot-password :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la réinitialisation.' });
  }
});

app.put('/api/user/email', attachUser, async (req, res) => {
  try {
    const newEmail = String(req.body?.email || '').trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!newEmail || !emailRegex.test(newEmail)) {
      return res.status(400).json({ error: 'Veuillez saisir une adresse e-mail valide.' });
    }

    const existingUser = await findUserByEmail(newEmail);
    if (existingUser && Number(existingUser.id) !== Number(req.currentUser.id)) {
      return res.status(409).json({ error: 'Cette adresse e-mail est déjà associée à un autre compte.' });
    }

    await pool.query('UPDATE users SET email = ? WHERE id = ?', [newEmail, req.currentUser.id]);
    const updatedRow = await findUserById(req.currentUser.id);
    const updatedUser = sanitizeUser(updatedRow);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'auth',
      actionType: 'EMAIL_UPDATED',
      referenceId: req.currentUser.id,
      details: `Nouvel email : ${newEmail}`
    });

    return res.json({
      message: 'Adresse e-mail mise à jour avec succès.',
      user: updatedUser
    });
  } catch (err) {
    console.error('Erreur PUT /api/user/email :', err);
    return res.status(500).json({ error: "Erreur serveur lors de la mise à jour de l'e-mail." });
  }
});

app.put('/api/user/password', attachUser, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await findUserById(req.currentUser.id);

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    const isOldValid = await verifyPassword(oldPassword, user.password_hash);
    if (!isOldValid) {
      return res.status(400).json({ error: 'Ancien mot de passe incorrect.' });
    }

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({
        error: 'Le nouveau mot de passe doit contenir au moins 8 caractères.'
      });
    }

    const hashedPassword = await bcrypt.hash(String(newPassword), 12);
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, user.id]);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'auth',
      actionType: 'PASSWORD_CHANGED',
      referenceId: req.currentUser.id,
      details: 'Modification du mot de passe'
    });

    return res.json({ message: 'Mot de passe mis à jour avec succès.' });
  } catch (err) {
    console.error('Erreur PUT /api/user/password :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la mise à jour du mot de passe.' });
  }
});

// --- Routes Super Admin (Rôles, Permissions, Blocage exclusif, Suppression) ---
app.put('/api/super-admin/user-role', attachUser, requireSuperAdmin, async (req, res) => {
  try {
    const { targetUserId, newRole, permissions } = req.body;

    if (!targetUserId || !['admin', 'client', 'delivery'].includes(newRole)) {
      return res.status(400).json({
        error: 'Paramètres invalides : targetUserId et newRole ("admin", "delivery" ou "client") sont requis.'
      });
    }

    if (String(targetUserId) === String(req.currentUser.id)) {
      return res.status(400).json({
        error: 'Vous ne pouvez pas modifier votre propre rôle.'
      });
    }

    const targetUser = await findUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur cible introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: "Le rôle d'un Super Admin ne peut pas être modifié."
      });
    }

    const nextPermissions =
      newRole === 'admin'
        ? parsePermissions(permissions, 'admin')
        : { ...EMPTY_PERMISSIONS };

    const updatedUser = await updateUserRoleAndPermissions(
      targetUserId,
      newRole,
      nextPermissions
    );

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'clients',
      actionType: 'ROLE_CHANGED',
      referenceId: targetUserId,
      details: `${updatedUser.name} -> rôle ${newRole}`
    });

    const roleLabel =
      newRole === 'admin'
        ? 'Administrateur'
        : newRole === 'delivery'
        ? 'Livreur'
        : 'Client';

    return res.json({
      message: `${updatedUser.name} a maintenant le rôle : ${roleLabel}.`,
      user: sanitizeUser(updatedUser)
    });
  } catch (err) {
    console.error('Erreur PUT /api/super-admin/user-role :', err);
    res.status(500).json({ error: 'Erreur serveur lors du changement de rôle.' });
  }
});

app.put('/api/super-admin/user-permissions', attachUser, requireSuperAdmin, async (req, res) => {
  try {
    const { targetUserId, permissions } = req.body;

    if (!targetUserId || !permissions || typeof permissions !== 'object') {
      return res.status(400).json({
        error: 'Paramètres invalides : targetUserId et un objet permissions sont requis.'
      });
    }

    const targetUser = await findUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur cible introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: 'Les droits du Super Admin sont complets et non modifiables.'
      });
    }

    if (targetUser.role !== 'admin') {
      return res.status(400).json({
        error: "Impossible de modifier des permissions d'admin sur un compte non-admin."
      });
    }

    const sanitizedPermissions = {
      can_manage_products: Boolean(permissions.can_manage_products),
      can_manage_orders: Boolean(permissions.can_manage_orders),
      can_manage_cashier: Boolean(permissions.can_manage_cashier),
      can_manage_clients: Boolean(permissions.can_manage_clients)
    };

    const updatedUser = await updateUserPermissionsOnly(targetUserId, sanitizedPermissions);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'clients',
      actionType: 'PERMISSIONS_UPDATED',
      referenceId: targetUserId,
      details: `Permissions mises à jour pour ${updatedUser.name}`
    });

    return res.json({
      message: `Permissions mises à jour pour ${updatedUser.name}.`,
      user: sanitizeUser(updatedUser)
    });
  } catch (err) {
    console.error('Erreur PUT /api/super-admin/user-permissions :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la mise à jour des permissions.' });
  }
});

// Blocage / Déblocage de compte : EXCLUSIVEMENT réservé au Super Admin
app.put('/api/admin/user-status', attachUser, requireSuperAdmin, async (req, res) => {
  try {
    const { userId, newStatus } = req.body;
    if (!userId || !['active', 'blocked'].includes(newStatus)) {
      return res.status(400).json({ error: 'Paramètres invalides.' });
    }

    const target = await findUserById(userId);
    if (!target) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }
    if (target.role === 'super_admin') {
      return res.status(403).json({ error: 'Impossible de bloquer un Super Admin.' });
    }

    await pool.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId]);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'clients',
      actionType: newStatus === 'blocked' ? 'CLIENT_BLOCKED' : 'CLIENT_UNBLOCKED',
      referenceId: userId,
      details: `Compte ${target.name} (${target.email}) -> ${newStatus}`
    });

    return res.json({
      message:
        newStatus === 'blocked'
          ? `Le compte de ${target.name} a été bloqué.`
          : `Le compte de ${target.name} a été réactivé.`
    });
  } catch (err) {
    console.error('Erreur PUT /api/admin/user-status :', err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.delete('/api/super-admin/users/:id', attachUser, requireSuperAdmin, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const targetUserId = Number(req.params.id);

    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      return res.status(400).json({ error: 'Identifiant utilisateur invalide.' });
    }

    if (targetUserId === Number(req.currentUser.id)) {
      return res.status(400).json({
        error: 'Vous ne pouvez pas supprimer votre propre compte Super Admin.'
      });
    }

    const [rows] = await connection.query(
      'SELECT id, name, email, role FROM users WHERE id = ? LIMIT 1',
      [targetUserId]
    );
    const targetUser = rows[0];

    if (!targetUser) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    if (targetUser.role === 'super_admin') {
      return res.status(403).json({
        error: 'Impossible de supprimer un compte Super Admin.'
      });
    }

    await connection.beginTransaction();
    await connection.query('DELETE FROM users WHERE id = ?', [targetUserId]);
    await connection.commit();

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'clients',
      actionType: 'USER_DELETED',
      referenceId: targetUserId,
      details: `Suppression du compte ${targetUser.name} (${targetUser.email})`
    });

    return res.json({
      message: `Le compte de ${targetUser.name} (${targetUser.email}) a été supprimé.`
    });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur DELETE /api/super-admin/users/:id :', err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(409).json({
        error:
          "Impossible de supprimer ce compte car il est lié à d'autres enregistrements (commandes, réservations, etc.)."
      });
    }
    return res.status(500).json({ error: 'Erreur serveur lors de la suppression du compte.' });
  } finally {
    connection.release();
  }
});

// --- Route Liste Utilisateurs ---
app.get('/api/admin/users', attachUser, async (req, res) => {
  try {
    const isSuper = req.currentUser.role === 'super_admin';
    const canManageClients = Boolean(req.currentUser.permissions?.can_manage_clients);
    const canManageOrders = Boolean(req.currentUser.permissions?.can_manage_orders);

    if (!isSuper && !canManageClients && !canManageOrders) {
      return res.status(403).json({
        error: 'Accès refusé : permission insuffisante pour consulter les utilisateurs.'
      });
    }

    const [rows] = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.role, u.status, u.permissions,
              COUNT(o.id) AS total_orders
       FROM users u
       LEFT JOIN orders o ON o.user_id = u.id
       GROUP BY u.id, u.name, u.email, u.phone, u.role, u.status, u.permissions
       ORDER BY u.id ASC`
    );

    const users = rows.map((row) => ({
      ...sanitizeUser(row),
      total_orders: Number(row.total_orders || 0)
    }));

    return res.json(users);
  } catch (err) {
    console.error('Erreur GET /api/admin/users :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la récupération des utilisateurs.' });
  }
});

// --- Produits & stocks ---
// Côté public / client : le prix inclut silencieusement les frais de livraison
app.get('/api/products', async (req, res) => {
  try {
    const userId = req.header('x-user-id');
    let requester = null;
    if (userId) {
      requester = await findUserById(userId);
    }

    const isPrivileged =
      requester &&
      (requester.role === 'super_admin' ||
        (requester.role === 'admin' &&
          parsePermissions(requester.permissions, requester.role).can_manage_products));

    const [rows] = await pool.query('SELECT * FROM products WHERE is_active = 1 ORDER BY id DESC');
    if (isPrivileged) {
      return res.json(rows.map(formatProductForAdmin));
    }
    return res.json(rows.map(formatProductForClient));
  } catch (err) {
    console.error('Erreur GET /api/products :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des produits.' });
  }
});

app.post('/api/products', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    const {
      product_type,
      name,
      category,
      price,
      delivery_fee,
      description,
      image_url,
      file_url,
      stock
    } = req.body;
    const safeType = product_type === 'digital' ? 'digital' : 'physical';
    const numericBasePrice = Number(price);
    const numericDeliveryFee =
      safeType === 'physical' ? Math.max(0, Number(delivery_fee ?? 0)) : 0;
    const numericStock = safeType === 'digital' ? 0 : Math.max(0, Number(stock ?? 0));

    if (!name || !category || !Number.isFinite(numericBasePrice) || numericBasePrice <= 0) {
      return res.status(400).json({ error: 'Nom, catégorie et prix valide sont requis.' });
    }

    const [result] = await pool.query(
      `INSERT INTO products
        (product_type, name, category, price, delivery_fee, description, image_url, file_url, stock)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        safeType,
        String(name).trim(),
        String(category).trim(),
        numericBasePrice,
        numericDeliveryFee,
        description || '',
        image_url || '',
        safeType === 'digital' ? file_url || '' : null,
        numericStock
      ]
    );

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'products',
      actionType: 'PRODUCT_CREATED',
      referenceId: result.insertId,
      amount: numericBasePrice + numericDeliveryFee,
      details: `Ajout article "${String(name).trim()}" (${safeType})`
    });

    return res.status(201).json({ id: result.insertId, message: 'Article ajouté avec succès.' });
  } catch (err) {
    console.error('Erreur POST /api/products :', err);
    return res.status(500).json({ error: "Erreur lors de l'ajout de l'article." });
  }
});

app.put('/api/products/:id', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    const productId = req.params.id;
    const {
      product_type,
      name,
      category,
      price,
      base_price,
      delivery_fee,
      description,
      image_url,
      file_url,
      stock
    } = req.body;
    const safeType = product_type === 'digital' ? 'digital' : 'physical';
    const numericBasePrice = Number(base_price !== undefined ? base_price : price);
    const numericDeliveryFee =
      safeType === 'physical' ? Math.max(0, Number(delivery_fee ?? 0)) : 0;
    const numericStock = safeType === 'digital' ? 0 : Math.max(0, Number(stock ?? 0));

    await pool.query(
      `UPDATE products
       SET product_type = ?,
           name = ?,
           category = ?,
           price = ?,
           delivery_fee = ?,
           description = ?,
           image_url = ?,
           file_url = ?,
           stock = ?
       WHERE id = ?`,
      [
        safeType,
        String(name).trim(),
        String(category).trim(),
        numericBasePrice,
        numericDeliveryFee,
        description || '',
        image_url || '',
        safeType === 'digital' ? file_url || '' : null,
        numericStock,
        productId
      ]
    );

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'products',
      actionType: 'PRODUCT_UPDATED',
      referenceId: productId,
      amount: numericBasePrice + numericDeliveryFee,
      details: `Mise à jour article "${String(name).trim()}"`
    });

    return res.json({ message: 'Article mis à jour.' });
  } catch (err) {
    console.error('Erreur PUT /api/products/:id :', err);
    return res.status(500).json({ error: "Erreur lors de la mise à jour de l'article." });
  }
});

app.delete('/api/products/:id', attachUser, requirePermission('can_manage_products'), async (req, res) => {
  try {
    const productId = req.params.id;
    await pool.query('DELETE FROM products WHERE id = ?', [productId]);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'products',
      actionType: 'PRODUCT_DELETED',
      referenceId: productId,
      details: `Suppression article #${productId}`
    });

    return res.json({ message: 'Article supprimé.' });
  } catch (err) {
    console.error('Erreur DELETE /api/products/:id :', err);
    return res.status(500).json({ error: "Erreur lors de la suppression de l'article." });
  }
});

// --- Commandes Client (Matériel = Paiement à la livraison / Numérique = Paiement simulé immédiat) ---
app.post('/api/orders', attachUser, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const {
      cartItems,
      deliveryInfo,
      digitalPaymentMode
    } = req.body;

    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ error: 'Votre panier est vide.' });
    }

    await connection.beginTransaction();

    // Regrouper les articles par produit
    const qtyMap = new Map();
    for (const item of cartItems) {
      const pid = Number(item.id);
      qtyMap.set(pid, (qtyMap.get(pid) || 0) + 1);
    }

    const productIds = Array.from(qtyMap.keys());
    const [dbProducts] = await connection.query(
      `SELECT * FROM products WHERE id IN (?) FOR UPDATE`,
      [productIds]
    );

    if (dbProducts.length !== productIds.length) {
      await connection.rollback();
      return res.status(404).json({ error: "Un ou plusieurs articles n'existent plus." });
    }

    let hasPhysical = false;
    let hasDigital = false;
    let baseAmount = 0;
    let deliveryFeeTotal = 0;
    let displayedTotal = 0;
    const preparedItems = [];

    for (const prod of dbProducts) {
      const qty = qtyMap.get(prod.id);
      const isDigital = prod.product_type === 'digital';
      if (isDigital) {
        hasDigital = true;
      } else {
        hasPhysical = true;
        if (Number(prod.stock) < qty) {
          await connection.rollback();
          return res.status(400).json({
            error: `Stock insuffisant pour "${prod.name}" (disponible : ${prod.stock}).`
          });
        }
      }

      const unitBase = Number(prod.price || 0);
      const unitFee = isDigital ? 0 : Number(prod.delivery_fee || 0);
      const unitPublic = Number((unitBase + unitFee).toFixed(2));

      baseAmount += unitBase * qty;
      deliveryFeeTotal += unitFee * qty;
      displayedTotal += unitPublic * qty;

      preparedItems.push({
        product_id: prod.id,
        product_name: prod.name,
        product_type: prod.product_type,
        category: prod.category,
        unit_base_price: unitBase,
        unit_delivery_fee: unitFee,
        unit_price: unitPublic,
        quantity: qty,
        file_url: isDigital ? prod.file_url || '' : null
      });
    }

    // Validation des coordonnées de livraison uniquement si commande contenant du matériel
    const country = String(deliveryInfo?.country || '').trim();
    const city = String(deliveryInfo?.city || '').trim();
    const commune = String(deliveryInfo?.commune || '').trim();
    const deliveryAddress = String(deliveryInfo?.delivery_address || '').trim();
    const deliveryPhone = String(deliveryInfo?.delivery_phone || '').trim();
    const deliveryNotes = String(deliveryInfo?.delivery_notes || '').trim() || null;

    if (hasPhysical) {
      if (!country || !city || !commune || !deliveryAddress || !deliveryPhone) {
        await connection.rollback();
        return res.status(400).json({
          error:
            'Informations de livraison incomplètes : pays, ville, commune, adresse exacte et téléphone sont obligatoires pour le matériel.'
        });
      }
    }

    // Mode et statut de paiement
    let paymentStatus = 'pay_on_delivery';
    let paymentMode = 'Paiement à la livraison (Cash / Mobile Money au livreur)';
    let simulationRef = null;
    let deliveryStatus = 'pending';

    if (!hasPhysical && hasDigital) {
      // Commande 100% numérique : simulation de paiement immédiate et accès direct aux fichiers
      const validDigitalModes = ['Mobile Money', 'Carte Bancaire', 'Virement Bancaire', 'Portefeuille Électronique'];
      const chosenMode = validDigitalModes.includes(digitalPaymentMode)
        ? digitalPaymentMode
        : 'Mobile Money';
      paymentStatus = 'paid';
      paymentMode = `${chosenMode} (Paiement numérique validé)`;
      simulationRef = `SIM-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
      deliveryStatus = 'not_applicable';
    } else if (hasPhysical && hasDigital) {
      paymentStatus = 'pay_on_delivery';
      paymentMode = `Paiement à la livraison (Matériel) + ${digitalPaymentMode || 'Mobile Money'} (E-book)`;
      simulationRef = `SIM-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
      deliveryStatus = 'pending';
    }

    const invoiceNumber = `FAC-TS-${new Date().getFullYear()}-${Date.now().toString().slice(-6)}`;

    const [orderRes] = await connection.query(
      `INSERT INTO orders
        (invoice_number, user_id, base_amount, delivery_fee_total, total_amount, displayed_total,
         has_physical, has_digital, payment_status, payment_mode, simulation_ref,
         delivery_status, country, city, commune, delivery_address, delivery_phone, delivery_notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        invoiceNumber,
        req.currentUser.id,
        baseAmount.toFixed(2),
        deliveryFeeTotal.toFixed(2),
        displayedTotal.toFixed(2),
        displayedTotal.toFixed(2),
        hasPhysical ? 1 : 0,
        hasDigital ? 1 : 0,
        paymentStatus,
        paymentMode,
        simulationRef,
        deliveryStatus,
        hasPhysical ? country : null,
        hasPhysical ? city : null,
        hasPhysical ? commune : null,
        hasPhysical ? deliveryAddress : null,
        hasPhysical ? deliveryPhone : null,
        hasPhysical ? deliveryNotes : null
      ]
    );

    const newOrderId = orderRes.insertId;

    for (const item of preparedItems) {
      await connection.query(
        `INSERT INTO order_items
          (order_id, product_id, product_name, product_type, category,
           unit_base_price, unit_delivery_fee, unit_price, quantity, file_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          newOrderId,
          item.product_id,
          item.product_name,
          item.product_type,
          item.category,
          item.unit_base_price,
          item.unit_delivery_fee,
          item.unit_price,
          item.quantity,
          item.file_url
        ]
      );

      if (item.product_type === 'physical') {
        await connection.query(
          'UPDATE products SET stock = GREATEST(0, stock - ?) WHERE id = ?',
          [item.quantity, item.product_id]
        );
      }
    }

    await connection.query(
      'UPDATE users SET total_orders = total_orders + 1 WHERE id = ?',
      [req.currentUser.id]
    );

    // Si commande 100% numérique payée immédiatement, enregistrer automatiquement en caisse
    if (!hasPhysical && hasDigital) {
      await connection.query(
        `INSERT INTO cashier_transactions
          (order_id, recorded_by_id, type, payment_method, amount, note)
         VALUES (?, ?, 'sale', 'mobile_money', ?, ?)`,
        [
          newOrderId,
          req.currentUser.id,
          displayedTotal.toFixed(2),
          `Vente numérique immédiate (${invoiceNumber}) - ${paymentMode}`
        ]
      );
    }

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'orders',
      actionType: 'ORDER_CREATED',
      referenceId: newOrderId,
      amount: displayedTotal,
      details: `Commande ${invoiceNumber} (${hasPhysical ? 'Matériel - Paiement livraison' : 'Numérique - Payé'})`,
      conn: connection
    });

    await connection.commit();

    const [createdRows] = await pool.query(
      `SELECT o.*, u.name AS client_name, u.email AS client_email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       WHERE o.id = ? LIMIT 1`,
      [newOrderId]
    );
    const [fullOrder] = await attachItemsToOrders(createdRows);

    return res.status(201).json({
      message: hasPhysical
        ? 'Commande enregistrée ! Paiement prévu à la livraison. Votre facture TechSetup Store est prête.'
        : 'Paiement numérique validé ! Votre facture est prête et votre e-book est téléchargeable.',
      order: fullOrder
    });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur POST /api/orders :', err);
    return res.status(500).json({ error: 'Erreur serveur lors de la validation de commande.' });
  } finally {
    connection.release();
  }
});

// Historique commandes d'un client (avec ses articles & liens e-books)
app.get('/api/orders/:userId', attachUser, async (req, res) => {
  try {
    const requestedUserId = Number(req.params.userId);
    if (
      req.currentUser.role === 'client' &&
      Number(req.currentUser.id) !== requestedUserId
    ) {
      return res.status(403).json({ error: 'Accès non autorisé.' });
    }

    const [rows] = await pool.query(
      `SELECT o.*, u.name AS client_name, u.email AS client_email
       FROM orders o
       JOIN users u ON u.id = o.user_id
       WHERE o.user_id = ?
       ORDER BY o.created_at DESC`,
      [requestedUserId]
    );

    const enriched = await attachItemsToOrders(rows);
    return res.json(enriched);
  } catch (err) {
    console.error('Erreur GET /api/orders/:userId :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des commandes.' });
  }
});

// --- Réservations Client (72h & acompte) ---
app.get('/api/reservations/:userId', attachUser, async (req, res) => {
  try {
    const requestedUserId = Number(req.params.userId);
    if (
      req.currentUser.role === 'client' &&
      Number(req.currentUser.id) !== requestedUserId
    ) {
      return res.status(403).json({ error: 'Accès non autorisé.' });
    }

    // Expiration automatique des réservations dépassant 72h
    const [expiredList] = await pool.query(
      `SELECT id, product_id FROM reservations
       WHERE status = 'active' AND expires_at <= NOW()`
    );
    for (const exp of expiredList) {
      await pool.query(`UPDATE reservations SET status = 'expired' WHERE id = ?`, [exp.id]);
      await pool.query(`UPDATE products SET stock = stock + 1 WHERE id = ?`, [exp.product_id]);
    }

    const [rows] = await pool.query(
      `SELECT * FROM reservations WHERE user_id = ? ORDER BY created_at DESC`,
      [requestedUserId]
    );
    return res.json(rows);
  } catch (err) {
    console.error('Erreur GET /api/reservations/:userId :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des réservations.' });
  }
});

app.post('/api/reservations', attachUser, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { productId, depositPaid } = req.body;
    await connection.beginTransaction();

    const [prodRows] = await connection.query(
      'SELECT * FROM products WHERE id = ? FOR UPDATE',
      [productId]
    );
    const product = prodRows[0];
    if (!product || product.product_type === 'digital') {
      await connection.rollback();
      return res.status(400).json({ error: 'Ce produit ne peut pas être réservé.' });
    }
    if (Number(product.stock) <= 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Produit en rupture de stock.' });
    }

    const publicTotal = Number(
      (Number(product.price || 0) + Number(product.delivery_fee || 0)).toFixed(2)
    );
    const minDeposit = Number((publicTotal * 0.1).toFixed(2));
    const numericDeposit = Number(depositPaid);

    if (!Number.isFinite(numericDeposit) || numericDeposit < minDeposit) {
      await connection.rollback();
      return res.status(400).json({
        error: `Acompte minimum de 10% requis ($${minDeposit.toFixed(2)}).`
      });
    }

    const [resInsert] = await connection.query(
      `INSERT INTO reservations
        (user_id, product_id, product_name, total_price, deposit_paid, status, expires_at)
       VALUES (?, ?, ?, ?, ?, 'active', DATE_ADD(NOW(), INTERVAL 72 HOUR))`,
      [
        req.currentUser.id,
        product.id,
        product.name,
        publicTotal,
        numericDeposit
      ]
    );

    await connection.query('UPDATE products SET stock = stock - 1 WHERE id = ?', [product.id]);

    await connection.query(
      `INSERT INTO cashier_transactions
        (reservation_id, recorded_by_id, type, payment_method, amount, note)
       VALUES (?, ?, 'deposit', 'mobile_money', ?, ?)`,
      [
        resInsert.insertId,
        req.currentUser.id,
        numericDeposit,
        `Acompte réservation #${resInsert.insertId} - ${product.name}`
      ]
    );

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'reservations',
      actionType: 'RESERVATION_CREATED',
      referenceId: resInsert.insertId,
      amount: numericDeposit,
      details: `Réservation 72h de "${product.name}" (acompte $${numericDeposit.toFixed(2)})`,
      conn: connection
    });

    await connection.commit();
    return res.status(201).json({
      message: 'Réservation confirmée pour 72h ! Retrouvez-la dans "Mes Réservations".'
    });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur POST /api/reservations :', err);
    return res.status(500).json({ error: 'Erreur lors de la réservation.' });
  } finally {
    connection.release();
  }
});

app.put('/api/reservations/cancel', attachUser, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { reservationId } = req.body;
    await connection.beginTransaction();

    const [rows] = await connection.query(
      'SELECT * FROM reservations WHERE id = ? FOR UPDATE',
      [reservationId]
    );
    const resv = rows[0];
    if (!resv) {
      await connection.rollback();
      return res.status(404).json({ error: 'Réservation introuvable.' });
    }
    if (
      req.currentUser.role === 'client' &&
      Number(resv.user_id) !== Number(req.currentUser.id)
    ) {
      await connection.rollback();
      return res.status(403).json({ error: 'Accès refusé.' });
    }
    if (resv.status !== 'active') {
      await connection.rollback();
      return res.status(400).json({ error: "Cette réservation n'est plus active." });
    }

    await connection.query(`UPDATE reservations SET status = 'cancelled' WHERE id = ?`, [
      reservationId
    ]);
    await connection.query('UPDATE products SET stock = stock + 1 WHERE id = ?', [
      resv.product_id
    ]);

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'reservations',
      actionType: 'RESERVATION_CANCELLED',
      referenceId: reservationId,
      details: `Annulation réservation #${reservationId} (${resv.product_name})`,
      conn: connection
    });

    await connection.commit();
    return res.json({ message: 'Réservation annulée et article remis en stock.' });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur PUT /api/reservations/cancel :', err);
    return res.status(500).json({ error: "Erreur lors de l'annulation." });
  } finally {
    connection.release();
  }
});

// --- Commandes & Livraison Admin (can_manage_orders) ---
app.get('/api/admin/orders', attachUser, requirePermission('can_manage_orders'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT o.*,
              u.name AS client_name,
              u.email AS client_email,
              c.name AS assigned_courier_name
       FROM orders o
       JOIN users u ON u.id = o.user_id
       LEFT JOIN users c ON c.id = o.assigned_courier_id
       ORDER BY o.created_at DESC`
    );
    const enriched = await attachItemsToOrders(rows);
    return res.json(enriched);
  } catch (err) {
    console.error('Erreur GET /api/admin/orders :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des commandes.' });
  }
});

// Liste des livreurs disponibles pour assignation
app.get('/api/admin/couriers', attachUser, requirePermission('can_manage_orders'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, email, phone, status
       FROM users
       WHERE role = 'delivery' AND status = 'active'
       ORDER BY name ASC`
    );
    return res.json(rows);
  } catch (err) {
    console.error('Erreur GET /api/admin/couriers :', err);
    return res.status(500).json({ error: 'Erreur chargement des livreurs.' });
  }
});

app.put(
  '/api/admin/orders/:id/delivery',
  attachUser,
  requirePermission('can_manage_orders'),
  async (req, res) => {
    try {
      const orderId = req.params.id;
      const {
        delivery_status,
        delivery_address,
        delivery_phone,
        delivery_notes,
        assigned_courier_id
      } = req.body;

      const allowedStatuses = [
        'pending',
        'preparing',
        'shipped',
        'delivered',
        'cancelled',
        'not_applicable'
      ];
      if (!allowedStatuses.includes(delivery_status)) {
        return res.status(400).json({ error: 'Statut de livraison invalide.' });
      }

      const courierId =
        assigned_courier_id === '' || assigned_courier_id === null || assigned_courier_id === undefined
          ? null
          : Number(assigned_courier_id);

      await pool.query(
        `UPDATE orders
         SET delivery_status = COALESCE(?, delivery_status),
             delivery_address = COALESCE(?, delivery_address),
             delivery_phone = COALESCE(?, delivery_phone),
             delivery_notes = COALESCE(?, delivery_notes),
             assigned_courier_id = ?,
             updated_by = ?
         WHERE id = ?`,
        [
          delivery_status,
          delivery_address ?? null,
          delivery_phone ?? null,
          delivery_notes ?? null,
          courierId,
          req.currentUser.id,
          orderId
        ]
      );

      const [rows] = await pool.query('SELECT * FROM orders WHERE id = ? LIMIT 1', [orderId]);
      if (!rows[0]) {
        return res.status(404).json({ error: 'Commande introuvable.' });
      }

      await logActivity({
        actorId: req.currentUser.id,
        actorName: req.currentUser.name,
        actorRole: req.currentUser.role,
        module: 'orders',
        actionType: 'DELIVERY_UPDATED',
        referenceId: orderId,
        details: `Commande #${orderId} -> statut livraison "${delivery_status}"${courierId ? ` (Livreur #${courierId})` : ''}`
      });

      return res.json({
        message: 'Suivi de livraison mis à jour.',
        order: rows[0]
      });
    } catch (err) {
      console.error('Erreur PUT /api/admin/orders/:id/delivery :', err);
      return res.status(500).json({ error: 'Erreur lors de la mise à jour de la livraison.' });
    }
  }
);

// --- Interface Livreur (role = 'delivery' ou Admin commandes / Super Admin) ---
app.get('/api/delivery/orders', attachUser, requireDeliveryOrAdmin, async (req, res) => {
  try {
    const user = req.currentUser;
    let query = `
      SELECT o.*,
             u.name AS client_name,
             u.email AS client_email,
             c.name AS assigned_courier_name
      FROM orders o
      JOIN users u ON u.id = o.user_id
      LEFT JOIN users c ON c.id = o.assigned_courier_id
      WHERE o.has_physical = 1
    `;
    const params = [];

    if (user.role === 'delivery') {
      // Le livreur voit les commandes qui lui sont assignées OU celles en attente d'attribution
      query += ` AND (o.assigned_courier_id = ? OR o.assigned_courier_id IS NULL)`;
      params.push(user.id);
    }

    query += ` ORDER BY FIELD(o.delivery_status, 'shipped', 'preparing', 'pending', 'delivered', 'cancelled'), o.created_at DESC`;

    const [rows] = await pool.query(query, params);
    const enriched = await attachItemsToOrders(rows);
    return res.json(enriched);
  } catch (err) {
    console.error('Erreur GET /api/delivery/orders :', err);
    return res.status(500).json({ error: 'Erreur lors du chargement des livraisons.' });
  }
});

// Le livreur confirme la livraison ET l'encaissement du paiement à la livraison
app.post('/api/delivery/orders/:id/confirm-delivery', attachUser, requireDeliveryOrAdmin, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const orderId = Number(req.params.id);
    const { payment_method, courier_note } = req.body;
    const validMethods = ['cash', 'mobile_money', 'card', 'bank_transfer'];
    const safeMethod = validMethods.includes(payment_method) ? payment_method : 'cash';

    await connection.beginTransaction();

    const [rows] = await connection.query(
      'SELECT * FROM orders WHERE id = ? FOR UPDATE',
      [orderId]
    );
    const order = rows[0];
    if (!order) {
      await connection.rollback();
      return res.status(404).json({ error: 'Commande introuvable.' });
    }

    if (order.delivery_status === 'delivered' && order.payment_status === 'paid') {
      await connection.rollback();
      return res.status(400).json({ error: 'Cette commande a déjà été signalée comme livrée et encaissée.' });
    }

    const methodLabel =
      safeMethod === 'mobile_money'
        ? 'Mobile Money (perçu à la livraison)'
        : safeMethod === 'card'
        ? 'Carte bancaire (perçu à la livraison)'
        : 'Espèces / Cash (perçu à la livraison)';

    await connection.query(
      `UPDATE orders
       SET delivery_status = 'delivered',
           payment_status = 'paid',
           payment_mode = ?,
           assigned_courier_id = COALESCE(assigned_courier_id, ?),
           delivered_by_id = ?,
           delivered_by_name = ?,
           delivered_at = NOW(),
           payment_collected_at = NOW(),
           delivery_notes = COALESCE(?, delivery_notes),
           updated_by = ?
       WHERE id = ?`,
      [
        methodLabel,
        req.currentUser.id,
        req.currentUser.id,
        req.currentUser.name,
        courier_note ? String(courier_note).trim() : null,
        req.currentUser.id,
        orderId
      ]
    );

    // Enregistrement automatique dans la caisse de l'entreprise
    await connection.query(
      `INSERT INTO cashier_transactions
        (order_id, recorded_by_id, type, payment_method, amount, note)
       VALUES (?, ?, 'sale', ?, ?, ?)`,
      [
        orderId,
        req.currentUser.id,
        safeMethod,
        Number(order.total_amount).toFixed(2),
        `Encaissement livraison ${order.invoice_number} par livreur ${req.currentUser.name}`
      ]
    );

    await logActivity({
      actorId: req.currentUser.id,
      actorName: req.currentUser.name,
      actorRole: req.currentUser.role,
      module: 'delivery',
      actionType: 'DELIVERY_AND_PAYMENT_CONFIRMED',
      referenceId: orderId,
      amount: Number(order.total_amount),
      details: `Commande ${order.invoice_number} livrée et payée ($${Number(order.total_amount).toFixed(2)}) par ${req.currentUser.name}`,
      conn: connection
    });

    await connection.commit();

    return res.json({
      message: `Livraison et paiement confirmés pour la commande #${orderId} ! Le rapport a été transmis aux administrateurs.`
    });
  } catch (err) {
    await connection.rollback();
    console.error('Erreur POST /api/delivery/orders/:id/confirm-delivery :', err);
    return res.status(500).json({ error: 'Erreur lors de la confirmation de livraison.' });
  } finally {
    connection.release();
  }
});

// --- Caisse (can_manage_cashier) ---
app.get(
  '/api/admin/cashier/summary',
  attachUser,
  requirePermission('can_manage_cashier'),
  async (req, res) => {
    try {
      const [totalsRows] = await pool.query(
        `SELECT
           COALESCE(SUM(CASE WHEN type IN ('sale', 'deposit', 'balance') THEN amount ELSE 0 END), 0) AS total_in,
           COALESCE(SUM(CASE WHEN type IN ('refund', 'expense') THEN amount ELSE 0 END), 0) AS total_out
         FROM cashier_transactions`
      );

      const [transactions] = await pool.query(
        `SELECT t.*, u.name AS recorded_by_name
         FROM cashier_transactions t
         LEFT JOIN users u ON u.id = t.recorded_by_id
         ORDER BY t.created_at DESC
         LIMIT 50`
      );

      const totalIn = Number(totalsRows[0]?.total_in || 0);
      const totalOut = Number(totalsRows[0]?.total_out || 0);

      return res.json({
        total_in: totalIn,
        total_out: totalOut,
        net_balance: totalIn - totalOut,
        transactions
      });
    } catch (err) {
      console.error('Erreur GET /api/admin/cashier/summary :', err);
      return res.status(500).json({ error: 'Erreur lors du calcul de la caisse.' });
    }
  }
);

app.post(
  '/api/admin/cashier/transactions',
  attachUser,
  requirePermission('can_manage_cashier'),
  async (req, res) => {
    const connection = await pool.getConnection();
    try {
      const { order_id, reservation_id, type, payment_method, amount, note } = req.body;
      const validTypes = ['sale', 'deposit', 'balance', 'refund', 'expense'];
      const validMethods = ['cash', 'mobile_money', 'card', 'bank_transfer', 'pay_on_delivery'];
      const numericAmount = Number(amount);

      if (!validTypes.includes(type) || !Number.isFinite(numericAmount) || numericAmount <= 0) {
        return res.status(400).json({ error: 'Type ou montant invalide.' });
      }

      const safeMethod = validMethods.includes(payment_method) ? payment_method : 'cash';

      await connection.beginTransaction();

      const [result] = await connection.query(
        `INSERT INTO cashier_transactions
          (order_id, reservation_id, type, payment_method, amount, note, recorded_by_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          order_id || null,
          reservation_id || null,
          type,
          safeMethod,
          numericAmount,
          note || null,
          req.currentUser.id
        ]
      );

      if (order_id) {
        const nextPaymentStatus =
          type === 'refund' ? 'refunded' : type === 'deposit' ? 'deposit_paid' : 'paid';
        await connection.query(
          'UPDATE orders SET payment_status = ?, updated_by = ? WHERE id = ?',
          [nextPaymentStatus, req.currentUser.id, order_id]
        );
      }

      await logActivity({
        actorId: req.currentUser.id,
        actorName: req.currentUser.name,
        actorRole: req.currentUser.role,
        module: 'cashier',
        actionType: `CASHIER_${type.toUpperCase()}`,
        referenceId: result.insertId,
        amount: numericAmount,
        details: note || `Opération caisse (${type})`,
        conn: connection
      });

      await connection.commit();

      return res.status(201).json({
        id: result.insertId,
        message: 'Mouvement de caisse enregistré.'
      });
    } catch (err) {
      await connection.rollback();
      console.error('Erreur POST /api/admin/cashier/transactions :', err);
      return res.status(500).json({ error: "Erreur lors de l'enregistrement en caisse." });
    } finally {
      connection.release();
    }
  }
);

// --- Rapports d'activité et de trafic (Admin selon accès / Super Admin global) ---
function buildPeriodSql(period, year, month, dateStr) {
  const safeYear = Number(year) || new Date().getFullYear();
  const safeMonth = Number(month) || new Date().getMonth() + 1;

  if (period === 'daily') {
    if (dateStr && /^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
      return { clause: 'DATE(created_at) = ?', params: [dateStr], label: `Journalier (${dateStr})` };
    }
    return { clause: 'DATE(created_at) = CURDATE()', params: [], label: "Journalier (Aujourd'hui)" };
  }
  if (period === 'weekly') {
    return {
      clause: 'YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1)',
      params: [],
      label: 'Hebdomadaire (Semaine en cours)'
    };
  }
  if (period === 'yearly') {
    return {
      clause: 'YEAR(created_at) = ?',
      params: [safeYear],
      label: `Annuel (${safeYear})`
    };
  }
  // Par défaut : mensuel
  return {
    clause: 'YEAR(created_at) = ? AND MONTH(created_at) = ?',
    params: [safeYear, safeMonth],
    label: `Mensuel (${String(safeMonth).padStart(2, '0')}/${safeYear})`
  };
}

app.get('/api/admin/reports', attachUser, async (req, res) => {
  try {
    const user = req.currentUser;
    const isSuper = user.role === 'super_admin';
    if (!isSuper && user.role !== 'admin') {
      return res.status(403).json({ error: 'Accès réservé aux administrateurs.' });
    }

    const period = ['daily', 'weekly', 'monthly', 'yearly'].includes(req.query.period)
      ? req.query.period
      : 'monthly';
    const scope = isSuper && req.query.scope === 'global' ? 'global' : isSuper ? 'global' : 'personal';

    const { clause, params, label } = buildPeriodSql(
      period,
      req.query.year,
      req.query.month,
      req.query.date
    );

    const perms = user.permissions || {};

    // 1. Logs d'activité (tous trafics pour Super Admin global, sinon filtré par acteur et modules autorisés)
    let logWhere = clause;
    const logParams = [...params];

    if (!isSuper) {
      const allowedModules = ['auth'];
      if (perms.can_manage_products) allowedModules.push('products');
      if (perms.can_manage_orders) allowedModules.push('orders', 'delivery');
      if (perms.can_manage_cashier) allowedModules.push('cashier');
      if (perms.can_manage_clients) allowedModules.push('clients', 'chatbot');

      logWhere += ` AND actor_id = ? AND module IN (${allowedModules.map(() => '?').join(',')})`;
      logParams.push(user.id, ...allowedModules);
    }

    const [logs] = await pool.query(
      `SELECT * FROM activity_logs WHERE ${logWhere} ORDER BY created_at DESC LIMIT 150`,
      logParams
    );

    // 2. Statistiques détaillées selon les permissions ou globales pour le Super Admin
    const stats = {
      period_label: label,
      scope,
      total_events: logs.length,
      orders: null,
      deliveries: null,
      cashier: null,
      clients: null,
      products: null,
      chatbot: null
    };

    if (isSuper || perms.can_manage_orders) {
      const [ordRows] = await pool.query(
        `SELECT
           COUNT(*) AS total_orders,
           COALESCE(SUM(total_amount), 0) AS total_sales_amount,
           SUM(CASE WHEN delivery_status = 'delivered' THEN 1 ELSE 0 END) AS delivered_count,
           SUM(CASE WHEN delivery_status IN ('pending', 'preparing', 'shipped') THEN 1 ELSE 0 END) AS pending_delivery_count,
           SUM(CASE WHEN payment_status = 'paid' THEN 1 ELSE 0 END) AS paid_orders_count,
           SUM(CASE WHEN payment_status = 'pay_on_delivery' THEN 1 ELSE 0 END) AS cod_pending_count
         FROM orders
         WHERE ${clause}`,
        params
      );
      stats.orders = ordRows[0];

      const [deliveryReports] = await pool.query(
        `SELECT id, invoice_number, total_amount, delivered_by_name, delivered_at, city, commune, payment_mode
         FROM orders
         WHERE delivery_status = 'delivered' AND ${clause.replace(/created_at/g, 'COALESCE(delivered_at, created_at)')}
         ORDER BY delivered_at DESC
         LIMIT 30`,
        params
      );
      stats.deliveries = deliveryReports;
    }

    if (isSuper || perms.can_manage_cashier) {
      const [cashRows] = await pool.query(
        `SELECT
           COUNT(*) AS tx_count,
           COALESCE(SUM(CASE WHEN type IN ('sale', 'deposit', 'balance') THEN amount ELSE 0 END), 0) AS total_in,
           COALESCE(SUM(CASE WHEN type IN ('refund', 'expense') THEN amount ELSE 0 END), 0) AS total_out
         FROM cashier_transactions
         WHERE ${clause}`,
        params
      );
      stats.cashier = {
        ...cashRows[0],
        net: Number(cashRows[0]?.total_in || 0) - Number(cashRows[0]?.total_out || 0)
      };
    }

    if (isSuper || perms.can_manage_clients) {
      const [cliRows] = await pool.query(
        `SELECT COUNT(*) AS new_clients FROM users WHERE role = 'client' AND ${clause}`,
        params
      );
      const [resvRows] = await pool.query(
        `SELECT COUNT(*) AS total_reservations, COALESCE(SUM(deposit_paid), 0) AS total_deposits
         FROM reservations WHERE ${clause}`,
        params
      );
      stats.clients = {
        new_clients: Number(cliRows[0]?.new_clients || 0),
        total_reservations: Number(resvRows[0]?.total_reservations || 0),
        total_deposits: Number(resvRows[0]?.total_deposits || 0)
      };
    }

    if (isSuper || perms.can_manage_products) {
      const [prodRows] = await pool.query(
        `SELECT
           COUNT(*) AS total_catalog,
           SUM(CASE WHEN product_type = 'physical' THEN 1 ELSE 0 END) AS physical_count,
           SUM(CASE WHEN product_type = 'digital' THEN 1 ELSE 0 END) AS digital_count,
           SUM(CASE WHEN product_type = 'physical' AND stock <= 2 THEN 1 ELSE 0 END) AS low_stock_count
         FROM products`
      );
      stats.products = prodRows[0];
    }

    if (isSuper) {
      const [chatRows] = await pool.query(
        `SELECT
           COUNT(*) AS total_messages,
           SUM(CASE WHEN sender = 'client' AND is_resolved = 0 THEN 1 ELSE 0 END) AS unresolved_complaints
         FROM chatbot_messages
         WHERE ${clause}`,
        params
      );
      stats.chatbot = chatRows[0];
    }

    return res.json({
      stats,
      logs
    });
  } catch (err) {
    console.error('Erreur GET /api/admin/reports :', err);
    return res.status(500).json({ error: 'Erreur lors de la génération du rapport.' });
  }
});

// --- Chatbot IA + Synthèse des lamentations / besoins clients ---
function analyzeClientMessageWithAI(rawMessage, clientName) {
  const text = String(rawMessage || '').trim();
  const lower = text.toLowerCase();

  let category = 'other';
  let sentiment = 'neutral';
  let aiReply = '';
  let summary = '';

  if (
    lower.includes('retard') ||
    lower.includes('tard') ||
    lower.includes('livraison') ||
    lower.includes('livreur') ||
    lower.includes('pas encore reçu') ||
    lower.includes('colis')
  ) {
    category = 'late_delivery';
    sentiment = lower.includes('retard') || lower.includes('pas encore') ? 'urgent' : 'neutral';
    summary = `Suivi / Retard de livraison signalé par ${clientName} : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName} 👋 ! Je comprends votre préoccupation concernant la livraison. ` +
      `Nos livraisons de matériel se font avec paiement à la livraison dès confirmation de votre adresse et commune. ` +
      `Votre signalement a été transmis en priorité au service livraison et à l'administration afin qu'un livreur vous contacte rapidement par téléphone.`;
  } else if (
    lower.includes('facture') ||
    lower.includes('paiement') ||
    lower.includes('payer') ||
    lower.includes('prix') ||
    lower.includes('remboursement')
  ) {
    category = 'payment_invoice';
    sentiment = lower.includes('remboursement') || lower.includes('problème') ? 'negative' : 'neutral';
    summary = `Question paiement / facture de ${clientName} : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName} ! Pour le matériel informatique, le règlement s'effectue directement à la livraison auprès de notre livreur (Espèces ou Mobile Money). ` +
      `Pour les livres numériques (E-books), le paiement est validé immédiatement en ligne. ` +
      `Vous pouvez imprimer votre facture officielle TechSetup Store à tout moment depuis "Mes Commandes".`;
  } else if (
    lower.includes('ebook') ||
    lower.includes('e-book') ||
    lower.includes('livre') ||
    lower.includes('télécharger') ||
    lower.includes('telecharger') ||
    lower.includes('pdf')
  ) {
    category = 'ebook_download';
    sentiment = 'neutral';
    summary = `Assistance téléchargement E-book pour ${clientName} : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName} 📚 ! Dès que vous validez l'achat d'un livre numérique, un bouton "Télécharger le livre" ainsi que votre facture apparaissent immédiatement. ` +
      `Vous pouvez également retrouver tous vos e-books achetés dans votre menu "Mes Commandes".`;
  } else if (
    lower.includes('réserv') ||
    lower.includes('reserv') ||
    lower.includes('acompte') ||
    lower.includes('72h')
  ) {
    category = 'reservation';
    sentiment = 'neutral';
    summary = `Demande sur les réservations 72h de ${clientName} : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName} ! Vous pouvez réserver tout matériel physique en stock pendant 72 heures avec un acompte minimum de 10 %. ` +
      `Gérez vos réservations actives directement dans l'onglet "Mes Réservations".`;
  } else if (
    lower.includes('plainte') ||
    lower.includes('déçu') ||
    lower.includes('mauvais') ||
    lower.includes('panne') ||
    lower.includes('cassé') ||
    lower.includes('souci') ||
    lower.includes('problème')
  ) {
    category = 'complaint';
    sentiment = 'negative';
    summary = `Lamentation / Réclamation client (${clientName}) : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName}, nous sommes sincèrement désolés pour ce désagrément 🙏. ` +
      `Votre réclamation a été enregistrée et synthétisée pour notre équipe de direction afin d'améliorer notre service et de vous apporter une solution rapide.`;
  } else {
    category = 'product_info';
    sentiment = 'positive';
    summary = `Demande d'information de ${clientName} : "${text.slice(0, 110)}"`;
    aiReply =
      `Bonjour ${clientName} 👋 ! Bienvenue sur l'assistant intelligent TechSetup Store. ` +
      `Je peux vous aider sur vos commandes, le paiement à la livraison, l'impression de votre facture, vos réservations 72h ou le téléchargement de vos e-books. Comment puis-je vous assister ?`;
  }

  return { category, sentiment, aiReply, summary };
}

app.get('/api/chatbot/messages/:sessionId', async (req, res) => {
  try {
    const sessionId = String(req.params.sessionId || '').trim();
    if (!sessionId) return res.json([]);
    const [rows] = await pool.query(
      `SELECT * FROM chatbot_messages WHERE session_id = ? ORDER BY created_at ASC, id ASC`,
      [sessionId]
    );
    return res.json(rows);
  } catch (err) {
    console.error('Erreur GET /api/chatbot/messages :', err);
    return res.status(500).json({ error: 'Erreur chargement discussion chatbot.' });
  }
});

app.post('/api/chatbot/message', async (req, res) => {
  try {
    const { sessionId, userId, clientName, clientEmail, message } = req.body;
    const cleanSession = String(sessionId || `sess-${Date.now()}`).trim();
    const cleanMsg = String(message || '').trim();

    if (!cleanMsg) {
      return res.status(400).json({ error: 'Veuillez saisir un message.' });
    }

    let resolvedUser = null;
    if (userId) {
      resolvedUser = await findUserById(userId);
    }

    const effectiveClientName =
      resolvedUser?.name || String(clientName || 'Client').trim() || 'Client';
    const effectiveClientEmail =
      resolvedUser?.email || String(clientEmail || '').trim() || null;

    const { category, sentiment, aiReply, summary } = analyzeClientMessageWithAI(
      cleanMsg,
      effectiveClientName
    );

    // Enregistrer le message du client
    await pool.query(
      `INSERT INTO chatbot_messages
        (session_id, user_id, client_name, client_email, sender, category, sentiment, message, ai_summary)
       VALUES (?, ?, ?, ?, 'client', ?, ?, ?, ?)`,
      [
        cleanSession,
        resolvedUser ? resolvedUser.id : null,
        effectiveClientName,
        effectiveClientEmail,
        category,
        sentiment,
        cleanMsg,
        summary
      ]
    );

    // Enregistrer la réponse immédiate de l'IA
    await pool.query(
      `INSERT INTO chatbot_messages
        (session_id, user_id, client_name, client_email, sender, category, sentiment, message, ai_summary)
       VALUES (?, ?, ?, ?, 'ai', ?, 'positive', ?, ?)`,
      [
        cleanSession,
        resolvedUser ? resolvedUser.id : null,
        effectiveClientName,
        effectiveClientEmail,
        category,
        aiReply,
        summary
      ]
    );

    await logActivity({
      actorId: resolvedUser ? resolvedUser.id : null,
      actorName: effectiveClientName,
      actorRole: resolvedUser ? resolvedUser.role : 'guest',
      module: 'chatbot',
      actionType: 'CHATBOT_CLIENT_QUERY',
      referenceId: cleanSession,
      details: summary
    });

    const [history] = await pool.query(
      `SELECT * FROM chatbot_messages WHERE session_id = ? ORDER BY created_at ASC, id ASC`,
      [cleanSession]
    );

    return res.status(201).json({
      reply: aiReply,
      messages: history
    });
  } catch (err) {
    console.error('Erreur POST /api/chatbot/message :', err);
    return res.status(500).json({ error: 'Erreur lors de la réponse du chatbot.' });
  }
});

// Synthèse IA des lamentations & besoins clients pour Admins / Super Admin
app.get('/api/admin/chatbot/insights', attachUser, async (req, res) => {
  try {
    const user = req.currentUser;
    const isSuper = user.role === 'super_admin';
    const canSeeClients = Boolean(user.permissions?.can_manage_clients);
    const canSeeOrders = Boolean(user.permissions?.can_manage_orders);

    if (!isSuper && !canSeeClients && !canSeeOrders) {
      return res.status(403).json({ error: 'Accès refusé aux synthèses chatbot.' });
    }

    const [byCategory] = await pool.query(
      `SELECT
         category,
         COUNT(*) AS total_count,
         SUM(CASE WHEN is_resolved = 0 THEN 1 ELSE 0 END) AS unresolved_count,
         SUM(CASE WHEN sentiment IN ('negative', 'urgent') THEN 1 ELSE 0 END) AS urgent_or_negative
       FROM chatbot_messages
       WHERE sender = 'client'
       GROUP BY category
       ORDER BY total_count DESC`
    );

    const [recentSummaries] = await pool.query(
      `SELECT id, session_id, user_id, client_name, client_email, category, sentiment, message, ai_summary, is_resolved, created_at
       FROM chatbot_messages
       WHERE sender = 'client'
       ORDER BY created_at DESC
       LIMIT 40`
    );

    return res.json({
      byCategory,
      recentSummaries
    });
  } catch (err) {
    console.error('Erreur GET /api/admin/chatbot/insights :', err);
    return res.status(500).json({ error: 'Erreur chargement synthèse chatbot.' });
  }
});

app.put('/api/admin/chatbot/:id/resolve', attachUser, async (req, res) => {
  try {
    const msgId = Number(req.params.id);
    await pool.query('UPDATE chatbot_messages SET is_resolved = 1 WHERE id = ?', [msgId]);
    return res.json({ message: 'Signalement marqué comme traité.' });
  } catch (err) {
    console.error('Erreur PUT /api/admin/chatbot/:id/resolve :', err);
    return res.status(500).json({ error: 'Erreur mise à jour signalement.' });
  }
});

ensureDatabaseSetup().then(() => {
  app.listen(PORT, () => {
    console.log(`Serveur TechSetup Store démarré sur http://localhost:${PORT}`);
  });
});