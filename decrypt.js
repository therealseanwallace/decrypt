import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { extname, basename } from 'node:path';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const getPassword = () => {
  const password = process.env.DECRYPTION_PASSWORD;
  if (!password) {
    throw new Error('DECRYPTION_PASSWORD environment variable is required');
  }
  return password;
};

const findFilePairs = () => {
  const files = readdirSync('.');
  const aesFiles = files.filter(file => extname(file) === '.aes');
  
  const pairs = aesFiles
    .map(aesFile => {
      const baseName = basename(aesFile, '.aes');
      const metadataFile = files.find(file => 
        basename(file, extname(file)) === baseName && 
        (extname(file) === '.json' || file.endsWith('.metadata'))
      );
      
      return metadataFile ? { aesFile, metadataFile } : null;
    })
    .filter(Boolean);
  
  return pairs;
};

const decryptFile = (aesFile, metadataFile, password) => {
  console.log(`Decrypting ${aesFile} using metadata from ${metadataFile}...`);
  
  try {
    // Read and parse metadata
    const metadata = JSON.parse(readFileSync(metadataFile, 'utf8'));
    
    // Extract encryption parameters
    const salt = Buffer.from(metadata.salt, 'base64');
    const iv = Buffer.from(metadata.iv, 'base64');
    const authTag = Buffer.from(metadata.authTag, 'base64');
    
    // Derive the key using the same parameters as encryption
    const key = pbkdf2Sync(password, salt, metadata.iterations, metadata.keyLength, 'sha256');
    
    // Read the encrypted file
    const encryptedData = readFileSync(aesFile);
    
    // Create and configure decipher
    const decipher = createDecipheriv(metadata.algorithm, key, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    const decryptedChunks = [
      decipher.update(encryptedData),
      decipher.final()
    ];
    
    const decryptedData = Buffer.concat(decryptedChunks);
    
    // Write the decrypted file
    const outputFile = `${basename(aesFile, '.aes')}.zip`;
    writeFileSync(outputFile, decryptedData);
    
    console.log(`✓ Successfully decrypted to ${outputFile}`);
    return true;
  } catch (error) {
    console.error(`✗ Failed to decrypt ${aesFile}: ${error.message}`);
    return false;
  }
};

const main = () => {
  try {
    const password = getPassword();
    const filePairs = findFilePairs();
    
    if (filePairs.length === 0) {
      console.log('No matching .aes and metadata file pairs found.');
      return;
    }
    
    console.log(`Found ${filePairs.length} file pair(s) to decrypt:`);
    filePairs.forEach(({ aesFile, metadataFile }) => {
      console.log(`  ${aesFile} + ${metadataFile}`);
    });
    console.log();
    
    const results = filePairs.map(({ aesFile, metadataFile }) => 
      decryptFile(aesFile, metadataFile, password)
    );
    
    const successful = results.filter(Boolean).length;
    const failed = results.length - successful;
    
    console.log();
    console.log(`Decryption complete: ${successful} successful, ${failed} failed`);
    
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

main();
