var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  categories: () => categories,
  insertCategorySchema: () => insertCategorySchema,
  insertProfessionalCategorySchema: () => insertProfessionalCategorySchema,
  insertProfessionalSchema: () => insertProfessionalSchema,
  insertRatingSchema: () => insertRatingSchema,
  insertUserSchema: () => insertUserSchema,
  professionalCategories: () => professionalCategories,
  professionals: () => professionals,
  ratings: () => ratings,
  recommendations: () => recommendations,
  systemSettings: () => systemSettings,
  systemSettingsSchema: () => systemSettingsSchema,
  users: () => users
});
import { pgTable, text, serial, integer, boolean, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  isAdmin: boolean("is_admin").notNull().default(false),
  isSuperAdmin: boolean("is_super_admin").notNull().default(false)
});
var categories = pgTable("categories", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  parentId: integer("parent_id").references(() => categories.id),
  slug: text("slug").notNull().unique(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow()
});
var professionals = pgTable("professionals", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  occupation: text("occupation").notNull(),
  description: text("description").notNull(),
  photoUrl: text("photo_url").notNull(),
  whatsapp: text("whatsapp").notNull(),
  detailedDescription: text("detailed_description").notNull(),
  location: text("location").notNull().default(""),
  averageRating: integer("average_rating").default(0),
  totalRatings: integer("total_ratings").default(0),
  categoryId: integer("category_id").references(() => categories.id),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var professionalCategories = pgTable("professional_categories", {
  id: serial("id").primaryKey(),
  professionalId: integer("professional_id").notNull().references(() => professionals.id),
  categoryId: integer("category_id").notNull().references(() => categories.id),
  createdAt: timestamp("created_at").defaultNow()
});
var ratings = pgTable("ratings", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  professionalId: integer("professional_id").notNull(),
  rating: integer("rating").notNull(),
  comment: text("comment"),
  createdAt: timestamp("created_at").defaultNow()
});
var recommendations = pgTable("recommendations", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  professionalId: integer("professional_id").notNull(),
  score: integer("score").notNull(),
  createdAt: timestamp("created_at").defaultNow()
});
var systemSettings = pgTable("system_settings", {
  id: serial("id").primaryKey(),
  showRatings: boolean("show_ratings").notNull().default(true),
  allowRatings: boolean("allow_ratings").notNull().default(true),
  updatedAt: timestamp("updated_at").defaultNow()
});
var insertUserSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
  isAdmin: z.boolean().optional().default(false),
  isSuperAdmin: z.boolean().optional().default(false)
});
var insertCategorySchema = createInsertSchema(categories);
var insertProfessionalSchema = createInsertSchema(professionals);
var insertProfessionalCategorySchema = createInsertSchema(professionalCategories);
var insertRatingSchema = createInsertSchema(ratings).pick({
  professionalId: true,
  rating: true,
  comment: true
});
var systemSettingsSchema = createInsertSchema(systemSettings);

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle(pool, { schema: schema_exports });

// server/storage.ts
import { eq, desc, and, sql } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
var PostgresSessionStore = connectPg(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    this.sessionStore = new PostgresSessionStore({
      pool,
      createTableIfMissing: true
    });
  }
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async getUserByUsername(username) {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }
  async getUsers() {
    return await db.select().from(users);
  }
  async createUser(insertUser) {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }
  async createUserWithRole(insertUser, isAdmin, isSuperAdmin) {
    const [user] = await db.insert(users).values({
      ...insertUser,
      isAdmin,
      isSuperAdmin
    }).returning();
    return user;
  }
  async updateUserRole(id, role) {
    const [user] = await db.update(users).set({
      isAdmin: role === "admin" || role === "superadmin",
      isSuperAdmin: role === "superadmin"
    }).where(eq(users.id, id)).returning();
    return user;
  }
  async getProfessionals() {
    return await db.select().from(professionals);
  }
  async getProfessional(id) {
    const [professional] = await db.select().from(professionals).where(eq(professionals.id, id));
    return professional;
  }
  async createProfessional(professional) {
    const [created] = await db.insert(professionals).values(professional).returning();
    return created;
  }
  async updateProfessional(id, update) {
    const [professional] = await db.update(professionals).set(update).where(eq(professionals.id, id)).returning();
    return professional;
  }
  async deleteProfessional(id) {
    const [deleted] = await db.delete(professionals).where(eq(professionals.id, id)).returning();
    return !!deleted;
  }
  async addRating(userId, rating) {
    const [newRating] = await db.insert(ratings).values({ ...rating, userId }).returning();
    await db.transaction(async (tx) => {
      const [professional] = await tx.select({
        totalRatings: professionals.totalRatings,
        averageRating: professionals.averageRating
      }).from(professionals).where(eq(professionals.id, rating.professionalId));
      const newTotal = (professional.totalRatings || 0) + 1;
      const newAverage = Math.round(
        ((professional.averageRating || 0) * (professional.totalRatings || 0) + rating.rating) / newTotal
      );
      await tx.update(professionals).set({
        totalRatings: newTotal,
        averageRating: newAverage
      }).where(eq(professionals.id, rating.professionalId));
    });
    return newRating;
  }
  async getProfessionalRatings(professionalId) {
    return await db.select().from(ratings).where(eq(ratings.professionalId, professionalId)).orderBy(desc(ratings.createdAt));
  }
  async getRecommendations(userId) {
    const userRatings = await db.select().from(ratings).where(eq(ratings.userId, userId));
    if (userRatings.length === 0) {
      return await db.select().from(professionals).orderBy(desc(professionals.averageRating)).limit(5);
    }
    const likedProfessionals = await db.select().from(professionals).where(
      sql`${professionals.occupation} IN (
          SELECT p.occupation FROM ${professionals} p
          JOIN ${ratings} r ON r.professional_id = p.id
          WHERE r.user_id = ${userId} AND r.rating >= 4
        )`
    ).orderBy(desc(professionals.averageRating)).limit(5);
    return likedProfessionals;
  }
  async updateRecommendations(userId) {
    const recommendedProfessionals = await this.getRecommendations(userId);
    await db.delete(recommendations).where(eq(recommendations.userId, userId));
    for (const professional of recommendedProfessionals) {
      await db.insert(recommendations).values({
        userId,
        professionalId: professional.id,
        score: professional.averageRating || 0
      });
    }
  }
  async deleteUser(id) {
    const [deleted] = await db.delete(users).where(eq(users.id, id)).returning();
    return !!deleted;
  }
  async updateUser(id, update) {
    if (update.password) {
      update.password = await hashPassword(update.password);
    }
    const [user] = await db.update(users).set(update).where(eq(users.id, id)).returning();
    return user;
  }
  // Implementación de métodos de categorías
  async createCategory(category) {
    const [created] = await db.insert(categories).values(category).returning();
    return created;
  }
  async updateCategory(id, update) {
    const [category] = await db.update(categories).set(update).where(eq(categories.id, id)).returning();
    return category;
  }
  async deleteCategory(id) {
    const [deleted] = await db.delete(categories).where(eq(categories.id, id)).returning();
    return !!deleted;
  }
  async getCategories() {
    return await db.select().from(categories).where(eq(categories.isActive, true));
  }
  async getCategoryBySlug(slug) {
    const [category] = await db.select().from(categories).where(eq(categories.slug, slug));
    return category;
  }
  async getSubcategories(parentId) {
    return await db.select().from(categories).where(eq(categories.parentId, parentId));
  }
  // Implementación de métodos de relación profesional-categoría
  async assignProfessionalToCategory(professionalId, categoryId) {
    const [assignment] = await db.insert(professionalCategories).values({ professionalId, categoryId }).returning();
    return assignment;
  }
  async removeProfessionalFromCategory(professionalId, categoryId) {
    const [deleted] = await db.delete(professionalCategories).where(
      and(
        eq(professionalCategories.professionalId, professionalId),
        eq(professionalCategories.categoryId, categoryId)
      )
    ).returning();
    return !!deleted;
  }
  async getProfessionalsByCategory(categoryId) {
    return await db.select().from(professionals).innerJoin(
      professionalCategories,
      eq(professionals.id, professionalCategories.professionalId)
    ).where(eq(professionalCategories.categoryId, categoryId));
  }
  async getCategoriesByProfessional(professionalId) {
    return await db.select().from(categories).innerJoin(
      professionalCategories,
      eq(categories.id, professionalCategories.categoryId)
    ).where(eq(professionalCategories.professionalId, professionalId));
  }
  async getSystemSettings() {
    const [settings] = await db.select().from(systemSettings).orderBy(desc(systemSettings.updatedAt)).limit(1);
    return settings;
  }
  async updateSystemSettings(update) {
    const [settings] = await db.insert(systemSettings).values({
      ...update,
      updatedAt: /* @__PURE__ */ new Date()
    }).onConflictDoUpdate({
      target: systemSettings.id,
      set: {
        ...update,
        updatedAt: /* @__PURE__ */ new Date()
      }
    }).returning();
    return settings;
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  const hashedPassword = `${buf.toString("hex")}.${salt}`;
  console.log("Generated hashed password:", {
    salt,
    hash: buf.toString("hex"),
    fullHash: hashedPassword
  });
  return hashedPassword;
}
async function comparePasswords(supplied, stored) {
  if (!stored || !stored.includes(".")) {
    console.log("Invalid password format:", { stored });
    return false;
  }
  try {
    const [hashed, salt] = stored.split(".");
    if (!hashed || !salt) {
      console.log("Missing hash or salt:", { hashed, salt });
      return false;
    }
    console.log("Comparing passwords:", {
      storedHash: hashed,
      salt,
      supplied
    });
    const hashedBuf = Buffer.from(hashed, "hex");
    const suppliedBuf = await scryptAsync(supplied, salt, 64);
    console.log("Generated supplied hash:", suppliedBuf.toString("hex"));
    return timingSafeEqual(hashedBuf, suppliedBuf);
  } catch (error) {
    console.error("Error comparing passwords:", error);
    return false;
  }
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 1e3 * 60 * 60 * 24
      // 24 hours
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        console.log("Attempting login for username:", username);
        const user = await storage.getUserByUsername(username);
        if (!user) {
          console.log("User not found");
          return done(null, false);
        }
        console.log("Found user:", {
          username: user.username,
          storedPassword: user.password,
          isAdmin: user.isAdmin,
          isSuperAdmin: user.isSuperAdmin
        });
        const isValid = await comparePasswords(password, user.password);
        console.log("Password validation result:", isValid);
        if (!isValid) {
          return done(null, false);
        }
        return done(null, user);
      } catch (error) {
        console.error("Login error:", error);
        return done(error);
      }
    })
  );
  passport.serializeUser((user, done) => {
    console.log("Serializing user:", { id: user.id, username: user.username });
    done(null, user.id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      console.log("Deserializing user with id:", id);
      const user = await storage.getUser(id);
      if (!user) {
        console.log("User not found during deserialization");
        return done(new Error("User not found"));
      }
      console.log("Successfully deserialized user:", { id: user.id, username: user.username });
      done(null, user);
    } catch (error) {
      console.error("Error during deserialization:", error);
      done(error);
    }
  });
  app2.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err, user) => {
      if (err) {
        console.error("Authentication error:", err);
        return next(err);
      }
      if (!user) {
        console.log("Authentication failed: Invalid credentials");
        return res.status(401).send("Invalid username or password");
      }
      req.login(user, (err2) => {
        if (err2) {
          console.error("Login error:", err2);
          return next(err2);
        }
        req.session.save((err3) => {
          if (err3) {
            console.error("Session save error:", err3);
            return next(err3);
          }
          console.log("User logged in successfully:", { id: user.id, username: user.username });
          res.json(user);
        });
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res, next) => {
    const userId = req.user?.id;
    console.log("Attempting to logout user:", userId);
    req.logout((err) => {
      if (err) {
        console.error("Logout error:", err);
        return next(err);
      }
      console.log("User logged out successfully:", userId);
      req.session.destroy((err2) => {
        if (err2) {
          console.error("Session destruction error:", err2);
          return next(err2);
        }
        res.clearCookie("connect.sid");
        res.sendStatus(200);
      });
    });
  });
  app2.get("/api/setup-admin", async (_req, res) => {
    try {
      const existingAdmin = await storage.getUserByUsername("soybassito");
      if (!existingAdmin) {
        const hashedPassword = await hashPassword("Nahuel@532");
        console.log("Creating admin user with hashed password:", hashedPassword);
        await storage.createUserWithRole(
          {
            username: "soybassito",
            password: hashedPassword
          },
          true,
          // isAdmin
          true
          // isSuperAdmin
        );
        res.json({ message: "Admin user created successfully" });
      } else {
        console.log("Existing admin found:", {
          username: existingAdmin.username,
          isAdmin: existingAdmin.isAdmin,
          isSuperAdmin: existingAdmin.isSuperAdmin
        });
        res.json({ message: "Admin user already exists" });
      }
    } catch (error) {
      console.error("Error in setup-admin:", error);
      res.status(500).json({ message: "Error creating admin user" });
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const hashedPassword = await hashPassword(req.body.password);
      const user = await storage.createUser({
        username: req.body.username,
        password: hashedPassword,
        isAdmin: false,
        isSuperAdmin: false
      });
      req.login(user, (err) => {
        if (err) return next(err);
        res.status(201).json(user);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      console.log("Unauthenticated request to /api/user");
      return res.sendStatus(401);
    }
    console.log("Authenticated user request:", { id: req.user.id, username: req.user.username });
    res.json(req.user);
  });
}

// server/routes.ts
import { ZodError } from "zod";
function requireAdmin(req) {
  if (!req.isAuthenticated()) {
    throw new Error("Unauthorized");
  }
  if (!req.user.isAdmin && !req.user.isSuperAdmin) {
    throw new Error("Forbidden");
  }
}
function requireSuperAdmin(req) {
  if (!req.isAuthenticated()) {
    throw new Error("Unauthorized");
  }
  if (!req.user.isSuperAdmin) {
    throw new Error("Forbidden");
  }
}
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.get("/api/professionals", async (_req, res) => {
    const professionals2 = await storage.getProfessionals();
    res.json(professionals2);
  });
  app2.get("/api/professionals/:id", async (req, res) => {
    const professional = await storage.getProfessional(Number(req.params.id));
    if (!professional) {
      return res.status(404).send("Professional not found");
    }
    res.json(professional);
  });
  app2.post("/api/professionals", async (req, res) => {
    try {
      requireAdmin(req);
      const professional = insertProfessionalSchema.parse(req.body);
      const created = await storage.createProfessional(professional);
      res.status(201).json(created);
    } catch (e) {
      if (e instanceof ZodError) {
        return res.status(400).json(e.errors);
      }
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.patch("/api/professionals/:id", async (req, res) => {
    try {
      requireAdmin(req);
      const professional = await storage.updateProfessional(
        Number(req.params.id),
        req.body
      );
      if (!professional) {
        return res.status(404).send("Professional not found");
      }
      res.json(professional);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.delete("/api/professionals/:id", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const success = await storage.deleteProfessional(Number(req.params.id));
      if (!success) {
        return res.status(404).send("Professional not found");
      }
      res.sendStatus(204);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/categories", async (_req, res) => {
    try {
      const categories2 = await storage.getCategories();
      res.json(categories2);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/categories/:slug", async (req, res) => {
    try {
      const category = await storage.getCategoryBySlug(req.params.slug);
      if (!category) {
        return res.status(404).send("Category not found");
      }
      res.json(category);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/categories/:id/subcategories", async (req, res) => {
    try {
      const subcategories = await storage.getSubcategories(Number(req.params.id));
      res.json(subcategories);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.post("/api/categories", async (req, res) => {
    try {
      requireAdmin(req);
      const category = insertCategorySchema.parse(req.body);
      const created = await storage.createCategory(category);
      res.status(201).json(created);
    } catch (e) {
      if (e instanceof ZodError) {
        return res.status(400).json(e.errors);
      }
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.patch("/api/categories/:id", async (req, res) => {
    try {
      requireAdmin(req);
      const category = await storage.updateCategory(Number(req.params.id), req.body);
      if (!category) {
        return res.status(404).send("Category not found");
      }
      res.json(category);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.delete("/api/categories/:id", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const success = await storage.deleteCategory(Number(req.params.id));
      if (!success) {
        return res.status(404).send("Category not found");
      }
      res.sendStatus(204);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.post("/api/professionals/:professionalId/categories/:categoryId", async (req, res) => {
    try {
      requireAdmin(req);
      const assignment = await storage.assignProfessionalToCategory(
        Number(req.params.professionalId),
        Number(req.params.categoryId)
      );
      res.status(201).json(assignment);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.delete("/api/professionals/:professionalId/categories/:categoryId", async (req, res) => {
    try {
      requireAdmin(req);
      const success = await storage.removeProfessionalFromCategory(
        Number(req.params.professionalId),
        Number(req.params.categoryId)
      );
      if (!success) {
        return res.status(404).send("Assignment not found");
      }
      res.sendStatus(204);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/categories/:categoryId/professionals", async (req, res) => {
    try {
      const professionals2 = await storage.getProfessionalsByCategory(Number(req.params.categoryId));
      res.json(professionals2);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/professionals/:professionalId/categories", async (req, res) => {
    try {
      const categories2 = await storage.getCategoriesByProfessional(Number(req.params.professionalId));
      res.json(categories2);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/users", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const users2 = await storage.getUsers();
      res.json(users2);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.post("/api/users", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const { username, password, role } = req.body;
      const userData = insertUserSchema.parse({ username, password });
      const existingUser = await storage.getUserByUsername(username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const user = await storage.createUserWithRole(
        userData,
        role === "admin" || role === "superadmin",
        role === "superadmin"
      );
      res.status(201).json(user);
    } catch (e) {
      if (e instanceof ZodError) {
        return res.status(400).json(e.errors);
      }
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.patch("/api/users/:id/role", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const userId = Number(req.params.id);
      const { role } = req.body;
      if (userId === req.user.id) {
        return res.status(400).send("Cannot modify your own role");
      }
      const updatedUser = await storage.updateUserRole(userId, role);
      if (!updatedUser) {
        return res.status(404).send("User not found");
      }
      res.json(updatedUser);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.delete("/api/users/:id", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const userId = Number(req.params.id);
      if (userId === req.user.id) {
        return res.status(400).send("No puedes eliminar tu propia cuenta");
      }
      const success = await storage.deleteUser(userId);
      if (!success) {
        return res.status(404).send("Usuario no encontrado");
      }
      res.sendStatus(204);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.patch("/api/users/:id", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const userId = Number(req.params.id);
      if (userId === req.user.id) {
        return res.status(400).send("No puedes modificar tu propia cuenta");
      }
      const user = await storage.updateUser(userId, req.body);
      if (!user) {
        return res.status(404).send("Usuario no encontrado");
      }
      res.json(user);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.post("/api/professionals/:id/rate", async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).send("Unauthorized");
      }
      const rating = insertRatingSchema.parse({
        ...req.body,
        professionalId: Number(req.params.id)
      });
      const newRating = await storage.addRating(req.user.id, rating);
      await storage.updateRecommendations(req.user.id);
      res.status(201).json(newRating);
    } catch (e) {
      if (e instanceof ZodError) {
        return res.status(400).json(e.errors);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/professionals/:id/ratings", async (req, res) => {
    try {
      const ratings2 = await storage.getProfessionalRatings(Number(req.params.id));
      res.json(ratings2);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/recommendations", async (req, res) => {
    try {
      if (!req.isAuthenticated()) {
        return res.status(401).send("Unauthorized");
      }
      const recommendations2 = await storage.getRecommendations(req.user.id);
      res.json(recommendations2);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.get("/api/system-settings", async (_req, res) => {
    try {
      const settings = await storage.getSystemSettings();
      res.json(settings);
    } catch (e) {
      res.status(500).send("Internal Server Error");
    }
  });
  app2.patch("/api/system-settings", async (req, res) => {
    try {
      requireSuperAdmin(req);
      const settings = await storage.updateSystemSettings(req.body);
      res.json(settings);
    } catch (e) {
      if (e instanceof Error) {
        return res.status(403).send(e.message);
      }
      res.status(500).send("Internal Server Error");
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  base: "/apress/",
  // 🔹 Cambia esto por el nombre de tu repositorio en GitHub
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client", "src"),
      "@shared": path.resolve(__dirname, "shared")
    }
  },
  root: path.resolve(__dirname, "client"),
  build: {
    outDir: path.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(__dirname2, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  try {
    log("Starting server initialization...");
    const server = await registerRoutes(app);
    app.use((err, _req, res, _next) => {
      const status = err.status || err.statusCode || 500;
      const message = err.message || "Internal Server Error";
      res.status(status).json({ message });
      console.error("Server error:", err);
    });
    if (app.get("env") === "development") {
      log("Setting up Vite for development...");
      await setupVite(app, server);
    } else {
      log("Setting up static files for production...");
      serveStatic(app);
    }
    const port = 5e3;
    server.listen({
      port,
      host: "0.0.0.0",
      reusePort: true
    }, () => {
      log(`Server started successfully on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
})();
