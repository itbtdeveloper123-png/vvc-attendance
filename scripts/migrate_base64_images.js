/*
  Migration script: migrate base64 images stored in Firestore messages to Firebase Storage

  > This script uses the Firebase Admin SDK and must be run from a secure environment.
  > DO NOT commit service account keys to the repository. Use environment variables or a secret manager.

  Steps to run:
  1. Install dependencies: npm install firebase-admin
  2. Ensure you have a service account JSON file and set GOOGLE_APPLICATION_CREDENTIALS to its path, or initialize admin with the credentials object.
  3. Update PROJECT_ID and STORAGE_BUCKET if needed.
  4. Run: node migrate_base64_images.js

  What the script does:
  - Scans all chat collections (chats/*/messages and groups/*/messages)
  - For messages that contain an "imageBase64" with length > 100, upload the image to Storage under chat_images/<roomId>/ and set imageUrl field in the message
  - Optionally clear imageBase64 (commented out) after successful upload

  IMPORTANT: Test on a small subset (limit) first and verify outputs before running on full dataset.
*/

const admin = require('firebase-admin');
const { Buffer } = require('buffer');

// Initialize admin (use GOOGLE_APPLICATION_CREDENTIALS env var or fill in credentials)
if (!admin.apps.length) {
  admin.initializeApp({
    // credential: admin.credential.applicationDefault(),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '<YOUR_BUCKET>.appspot.com',
  });
}

const db = admin.firestore();
const bucket = admin.storage().bucket();

async function migrateCollection(collectionPath, limit = 200) {
  console.log('Scanning', collectionPath);
  const rooms = await db.collection(collectionPath).listDocuments();
  for (const roomDoc of rooms) {
    const roomId = roomDoc.id;
    console.log('Room:', roomId);
    const messagesRef = roomDoc.collection('messages');
    const snapshot = await messagesRef.limit(limit).get();
    for (const msgDoc of snapshot.docs) {
      const data = msgDoc.data();
      const base64 = data.imageBase64;
      if (base64 && typeof base64 === 'string' && base64.length > 100) {
        try {
          console.log('Migrating message', msgDoc.id);
          const buffer = Buffer.from(base64, 'base64');
          const fileName = `chat_images/${roomId}/${Date.now()}_${msgDoc.id}.jpg`;
          const file = bucket.file(fileName);
          await file.save(buffer, { contentType: 'image/jpeg' });
          const [url] = await file.getSignedUrl({ action: 'read', expires: '03-01-2500' });

          await msgDoc.ref.update({ imageUrl: url });
          // Optionally clear base64 to save space:
          // await msgDoc.ref.update({ imageBase64: admin.firestore.FieldValue.delete() });
          console.log('Migrated', msgDoc.id);
        } catch (e) {
          console.error('Failed to migrate', msgDoc.id, e);
        }
      }
    }
  }
}

(async () => {
  try {
    // Migrate top-level chats and groups (adjust as needed)
    await migrateCollection('chats');
    await migrateCollection('groups');
    console.log('Done migration pass');
  } catch (e) {
    console.error(e);
  }
})();
