-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "login" TEXT NOT NULL,
    "password" TEXT,
    "isTwoFaEnabled" BOOLEAN DEFAULT false,
    "twoFaSecret" TEXT,
    "twoFaRecoveryCode" TEXT
);
INSERT INTO "new_User" ("email", "id", "isTwoFaEnabled", "login", "password", "twoFaRecoveryCode", "twoFaSecret") SELECT "email", "id", "isTwoFaEnabled", "login", "password", "twoFaRecoveryCode", "twoFaSecret" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_login_key" ON "User"("login");
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;
