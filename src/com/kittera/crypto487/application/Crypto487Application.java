package com.kittera.crypto487.application;

import com.kittera.crypto487.lib.E521CurveLib;
import com.kittera.crypto487.lib.E521Point;
import com.kittera.crypto487.lib.HashLib;
import com.kittera.crypto487.util.ArrayUtils;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

import static com.kittera.crypto487.lib.E521CurveLib.*;

/**
 * This application provides, or attempts to provide, up to 13 cryptographic services
 * including encryption, decryption, hashing,
 */
public class Crypto487Application {

/////////////////////////////////////////////////////////////////// Utility Objects //////
   
   
   private static final SecureRandom myRand = new SecureRandom();
   
   private static final PrintStream STDOUT = System.out;
   
   
/////////////////////////////////////////////////////////////////// Utility Objects //////
////////////////////////////////////////////////////////////////// Main Application //////
   
   /**
    * Program entry point.
    * @param args not used
    */
   public static void main(String... args) {
      //set up i/o objects
      Scanner console = new Scanner(System.in);
      intro();
      promptLoop(console);
      System.exit(0);
   }
   
   /**
    * Prints program introduction.
    */
   private static void intro() {
      STDOUT.println("\n Welcome to the Multi-Service Cryptography Suite");
      STDOUT.println(" By Kittera Ashleigh McCloud\n");
   }
   
   /**
    * Program prompt loop, quits upon detection of proper
    * @param console one Scanner to scan them all
    */
   private static void promptLoop(Scanner console) {
      int opNum;
      String input;
      
      while (true) {
         STDOUT.println(" Please choose an option from the menu:");
         for (MainMenuOption opt : MainMenuOption.values()) {
            STDOUT.println("  " + opt.optionNumber + " - " + opt.promptString);
         }
         STDOUT.print("Option: ");
         if (console.hasNext()) {
            input = console.next();
            if (detectQuit(input)) quit(console);
            else try {
               opNum = Integer.parseInt(input);
               if (opNum == MainMenuOption.QUIT.optionNumber) quit(console);
               else if (opNum < 1 || opNum > MainMenuOption.QUIT.optionNumber)
                  throw new NumberFormatException("Option out of range.");
               else enterSubMenu(opNum, console);
            } catch (NumberFormatException nfe) {
               STDOUT.println("Sorry, that input didn't work.");
               askRetry(console);
            }
         }
      }
   }
   
   /**
    * This method chooses the appropriate call for the option given
    * @param opNum chosen option value
    * @param console one Scanner to scan them all
    */
   private static void enterSubMenu(int opNum, Scanner console) {
      switch (MainMenuOption.values()[opNum - 1]) {
         case HASHFILE -> hashFile(console);
         case HASHTEXT -> hashText(console);
         case SYMMENC -> encryptFileSymmetric(console);
         case SYMMDEC -> decryptFileSymmetric(console);
         case AUTHTAG -> fileAuthTag(console);
         case GENKEYPAIR -> keyPair(console);
         case ELLIPTENC -> encryptFileElliptic(console);
         case ELLIPTTEXTENC -> encryptTextElliptic(console);
         case ELLIPTDEC -> decryptFileElliptic(console);
         case ELLIPTTEXTDEC -> decryptTextElliptic(console);
         case SIGNFILE -> signFile(console);
         case VERIFYSIG -> verifySig(console);
         case CRYPTENVEL -> encryptAndSignFile(console);
         case QUIT -> quit(console);
      }
   }
   
   /**
    * Implements the file hashing service in the application.
    * @param console one Scanner to scan them all
    */
   private static void hashFile(Scanner console) {
      byte[] fileBytes, hashBytes;
      String in;
      BigInteger hash;
      
      STDOUT.println("File Hashing");
      STDOUT.println("File must be in same directory as the program.\n");
      STDOUT.print("Name of the file to be hashed?: ");
      
      in = console.next();
      try {
         fileBytes = Files.readAllBytes(Paths.get(in));
         hashBytes = hashByteArray(fileBytes);
         hash = new BigInteger(1, hashBytes);
         STDOUT.println("File hashed:\n" + hash.toString(16));
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) hashFile(console);
         else askExit(console);
      }
   }
   
   /**
    * Implements the file hashing service in the application.
    * @param console one Scanner to scan them all
    */
   private static void hashText(Scanner console) {
      byte[] hashBytes;
      String in;
      BigInteger hash;
   
      STDOUT.println("Text Input Hashing");
      STDOUT.print("Type in a message to hash: ");
   
      in = console.next();
      hashBytes = hashByteArray(in.getBytes());
      hash = new BigInteger(1, hashBytes);
      STDOUT.println("Text hashed:\n" + hash.toString(16));
      askExit(console);
   }
   
   /**
    * Provides prompts and interactions for symmetrically encrypting files.
    * @param console one Scanner to scan them all
    */
   private static void encryptFileSymmetric(Scanner console) {
      byte[] fileBytes, tagFileBytes;
      String fileName, passPhrase, saltVal, tagVal;
      SymmetriCryptogram cGram;
      Path cryptFilePath, auxFilePath;
      
   
      STDOUT.println("File Encryption using passphrase");
      STDOUT.println("File must be in same directory as the program.\n");
   
      STDOUT.print("Name of the file to be encrypted?: ");
      fileName = console.next();
      cryptFilePath = Paths.get(fileName + "crypt");
      auxFilePath = Paths.get(fileName + "crypttag");
      
      STDOUT.print("Passphrase?: ");
      passPhrase = console.next();
      
      try {
         fileBytes = Files.readAllBytes(Paths.get(fileName));
         cGram = encryptByteArray(fileBytes, passPhrase.getBytes());
         Files.write(cryptFilePath, cGram.cryptogram);
         STDOUT.println("File encrypted and written to new file with \"crypt\" appended" +
               " to the file extension.");
        
         // to get a printable hex value
         saltVal = new BigInteger(1, cGram.z)
               .toString(16)
               .toUpperCase();
         tagVal = new BigInteger(1, cGram.authTag)
               .toString(16)
               .toUpperCase();
         STDOUT.printf(
               "Your salt is: %s\nYour authentication tag is: %s\n", saltVal, tagVal
         );
         
         //write aux information to another file
         tagFileBytes = ArrayUtils.mergeByteArrays(cGram.z, cGram.authTag);
         Files.write(auxFilePath, tagFileBytes);
         STDOUT.println("Salt and auth tag have been written to another file with " +
               "\"crypttag\" appended to its file extension.");
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) encryptFileSymmetric(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactions for decrypting symmetrically encrypted files.
    * @param console one Scanner to scan them all
    */
   private static void decryptFileSymmetric(Scanner console) {
      byte[] fileBytes, tagFileBytes, decryptedBytes = null;
      String tagFileName, fileName, passPhrase;
      SymmetriCryptogram cGram;
      Path filePath;
      
      STDOUT.println("File Decryption using passphrase");
      STDOUT.println("Files must be in same directory as the program.\n");
   
      STDOUT.print("Name of the file to be decrypted?: ");
      fileName = console.next();
   
      STDOUT.print("Tag File?: ");
      tagFileName = console.next();
   
      STDOUT.print("Passphrase?: ");
      passPhrase = console.next();
      
      filePath = Paths.get(fileName);
      try {
         fileBytes = Files.readAllBytes(filePath);
         tagFileBytes = Files.readAllBytes(Paths.get(tagFileName));
   
         cGram = new SymmetriCryptogram(
               Arrays.copyOfRange(tagFileBytes, 0, 64),
               fileBytes,
               Arrays.copyOfRange(tagFileBytes, 64, tagFileBytes.length)
         );
         decryptedBytes = deCryptogram(cGram, passPhrase.getBytes());
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) decryptFileSymmetric(console);
         else askExit(console);
      }
      
      // if authentication fails, deCryptogram returns null instead of bytes
      if (Objects.nonNull(decryptedBytes)) {
         try { // to write the decrypted bytes to a file
            Files.write(filePath, decryptedBytes);
            STDOUT.println("File decrypted and written back.");
         } catch (IOException ioe) {
            STDOUT.print("IO Error. ");
            if (askRetry(console)) decryptFileSymmetric(console);
            else askExit(console);
         }
      } else {
         STDOUT.println("Authentication failed. Could not decrypt.");
      }
      askExit(console);
   }
   
   /**
    * Provides prompts and interactions for generating MACs from given files.
    * @param console one Scanner to scan them all
    */
   private static void fileAuthTag(Scanner console) {
      byte[] fileBytes, tagBytes;
      String fileName, passPhrase, tagVal;
      
      STDOUT.println("Generate Authentication Tag for a file");
      STDOUT.println("File must be in same directory as the program.\n");
      
      STDOUT.print("File name?: ");
      fileName = console.next();
      
      STDOUT.print("Passphrase?: ");
      passPhrase = console.next();
      
      try {
         fileBytes = Files.readAllBytes(Paths.get(fileName));
         tagBytes = authTag(fileBytes, passPhrase.getBytes());
         tagVal = new BigInteger(1, tagBytes).toString(16).toUpperCase();
         STDOUT.printf("Authentication tag: %s", tagVal);
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) fileAuthTag(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactions for generating elliptic key pairs.
    * @param console one Scanner to scan them all
    */
   private static void keyPair(Scanner console) {
      boolean privWrite;
      byte[] pubBytes, privBytes;
      ECKeyPair keys;
      Path pubFilePath, privFilePath;
      String passphrase, pubKeyString;
      SymmetriCryptogram privKeyGram;
      
      STDOUT.println("Generate an elliptic key pair using a passphrase");
      STDOUT.println("Public key will be written to a .key file. Optionally, the private " +
            "key can be written to a .keycrypt file encrypted under the same passphrase.");
      
      STDOUT.print("Passphrase?: ");
      passphrase = console.next();
      
      STDOUT.print("Write private key to file as well? (y/n): ");
      privWrite = detectYes(console.next());
      
      keys = generateKeyPair(passphrase.getBytes());
      pubBytes = keys.myPublicKey.toByteArray();
      privBytes = keys.myPrivKeyBytes;
      pubKeyString = new BigInteger(1, pubBytes).toString(16).toUpperCase();
      STDOUT.printf("Public Key (in base16): %s\n", pubKeyString);
      
      pubFilePath = Paths.get("pub.key");
      privFilePath = Paths.get("priv.keycrypt" );
      
      try {
         Files.write(pubFilePath, pubBytes);
         STDOUT.println("Public key has been written to \"pub.key\"");
         if (privWrite) {
            privKeyGram = encryptByteArray(privBytes, passphrase.getBytes());
            Files.write(privFilePath, privKeyGram.cryptogram);
            STDOUT.println("Private key has been encrypted and written to priv.keycrypt");
         }
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) keyPair(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactions for encrypting files elliptically.
    * @param console one Scanner to scan them all
    */
   private static void encryptFileElliptic(Scanner console) {
      byte[] fileBytes, pubKeyBytes, tagFileBytes;
      String fileName, pubKeyFile, saltVal, tagVal;
      E521Point pubKey;
      ElliptiCryptogram eGram;
      Path cryptFilePath, auxFilePath;
      
      STDOUT.println("Elliptic File Encryption using public key from file");
      STDOUT.println("FileS must be in same directory as the program.\n");
      
      STDOUT.print("Name of the public key file?: ");
      pubKeyFile = console.next();
      
      STDOUT.print("Name of the file to be encrypted?: ");
      fileName = console.next();
      
      cryptFilePath = Paths.get(fileName + "eccrypt");
      auxFilePath = Paths.get(fileName + "eccrypttag");
      
      try {
         pubKeyBytes = Files.readAllBytes(Paths.get(pubKeyFile));
         pubKey = pointFromBytes(pubKeyBytes);
         fileBytes = Files.readAllBytes(Paths.get(fileName));
         
         eGram = encryptByteArray(fileBytes, pubKey);
         Files.write(cryptFilePath, eGram.cryptogram);
         STDOUT.println("File encrypted and written to new file with \"eccrypt\" appended" +
               " to the file extension.");
         
         // to get a printable hex value
         saltVal = new BigInteger(1, eGram.zPt.toByteArray())
               .toString(16)
               .toUpperCase();
         tagVal = new BigInteger(1, eGram.authTag)
               .toString(16)
               .toUpperCase();
         STDOUT.printf(
               "Your salt is: %s\nYour authentication tag is: %s\n",
               saltVal, tagVal
         );
         
         //write aux information to another file
         tagFileBytes = ArrayUtils.mergeByteArrays(eGram.zPt.toByteArray(), eGram.authTag);
         Files.write(auxFilePath, tagFileBytes);
         STDOUT.println("Salt and auth tag have been written to another file with " +
               "\"eccrypttag\" appended to its file extension.");
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) encryptFileElliptic(console);
         else askExit(console);
      } catch (IllegalArgumentException iae) {
         STDOUT.print("Failed to reconstruct the curve point from that public key file. ");
         if (askRetry(console)) encryptFileElliptic(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactions for decrypting files elliptically.
    * @param console one Scanner to scan them all
    */
   private static void decryptFileElliptic(Scanner console) {
      byte[] fileBytes, tagFileBytes, decryptedBytes;
      String tagFileName, fileName, passPhrase;
      ElliptiCryptogram eGram;
      Path filePath;
      
      STDOUT.println("Elliptic File Decryption using passphrase");
      STDOUT.println("Files must be in same directory as the program.\n");
      
      STDOUT.print("Name of the file to be decrypted?: ");
      fileName = console.next();
   
      STDOUT.print("Tag File?: ");
      tagFileName = console.next();
   
      STDOUT.print("Passphrase?: ");
      passPhrase = console.next();
   
      filePath = Paths.get(fileName);
      try {
         fileBytes = Files.readAllBytes(filePath);
         tagFileBytes = Files.readAllBytes(Paths.get(tagFileName));

         eGram = new ElliptiCryptogram(
               pointFromBytes(Arrays.copyOfRange(tagFileBytes, 0, EC_PT_BYTELEN)),
               fileBytes,
               Arrays.copyOfRange(tagFileBytes, EC_PT_BYTELEN, tagFileBytes.length)
         );
   
         // if authentication fails, deCryptogram returns null instead of bytes
         decryptedBytes = deCryptogram(eGram, passPhrase.getBytes());
         if (Objects.nonNull(decryptedBytes)) {
            try { // to write the decrypted bytes to a file
               Files.write(filePath, decryptedBytes);
               STDOUT.println("File decrypted and written back.");
            } catch (IOException ioe) {
               STDOUT.print("IO Error. ");
               if (askRetry(console)) decryptFileElliptic(console);
               else askExit(console);
            }
         } else {
            STDOUT.println("Authentication failed. Could not decrypt.");
         }
         askExit(console);
      }
      catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) decryptFileElliptic(console);
         else askExit(console);
      }
      catch (IllegalArgumentException iae) {
         STDOUT.print("Failed to parse that public key file. ");
         if (askRetry(console)) encryptFileElliptic(console);
         else askExit(console);
      }

      
   }
   
   /**
    * Provides prompts and interactions for digitally signing files.
    * @param console one Scanner to scan them all
    */
   private static void signFile(Scanner console) {
      byte[] fileBytes, pwBytes;
      Path filePath;
      DigitalSignature sig;
      String fileName;
      
      STDOUT.println("Sign a file with a passphrase");
      STDOUT.println("File must be in same directory as the program.");
      STDOUT.println("Signature will be written to a new file with \"signature\" appended to the file extension.\n");
   
   
      STDOUT.print("Name of the file to be signed?: ");
      fileName = console.next();
      filePath = Paths.get(fileName);
   
      STDOUT.print("Passphrase?: ");
      pwBytes = console.next().getBytes();
      
      try {
         fileBytes = Files.readAllBytes(filePath);
         sig = signByteArray(fileBytes, pwBytes);
         sig.toFile(Paths.get(fileName + "signature"));
         STDOUT.printf(
               "Your signature has been written to \"%s\"\n",
               fileName + "signature"
         );
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) signFile(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactions for verifying digital signatures.
    * @param console one Scanner to scan them all
    */
   private static void verifySig(Scanner console) {
      boolean verified;
      byte[] origFileBytes;
      Path sigFilePath, origFilePath, pubKeyFilePath;
      E521Point pubKey;
      DigitalSignature sig;
      String sigFileName;
   
      STDOUT.println("Verify signature of a file signed with a passphrase under PKI");
      STDOUT.println("Signature file and original file must both be in same directory as the program.");
   
   
      STDOUT.print("Name of the signed file?: ");
      origFilePath = Paths.get(console.next());
   
      STDOUT.print("Name of the signature file?: ");
      sigFileName = console.next();
      sigFilePath = Paths.get(sigFileName);
   
      STDOUT.print("Name of the public key file?: ");
      pubKeyFilePath = Paths.get(console.next());
   
   
      try {
         origFileBytes = Files.readAllBytes(origFilePath);
         STDOUT.println("Signed file successfully read.");
         sig = DigitalSignature.fromFile(sigFilePath);
         STDOUT.println("Signature file successfully read.");
         pubKey = pointFromBytes(Files.readAllBytes(pubKeyFilePath));
         STDOUT.println("Public key file successfully read.");
         verified = verifySignature(sig, origFileBytes, pubKey);
         STDOUT.printf(
               "\nSignature Verification Result: %s\n",
               verified? "VALID" : "NOT VALID"
         );
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error. ");
         if (askRetry(console)) verifySig(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactivity for elliptic encryption of text input by the user
    * instead of encrypting a file.
    * @param console one Scanner to scan them all
    */
   private static void encryptTextElliptic(Scanner console) {
      byte[] textBytes, pubKeyBytes;
      String pubKeyFile, saltVal, tagVal, cText;
      E521Point pubKey;
      ElliptiCryptogram eGram;
      
      STDOUT.println("Elliptic Text Encryption using public key from file");
   
      STDOUT.print("Name of the public key file?: ");
      pubKeyFile = console.next();
   
      STDOUT.print("Text to be encrypted?: ");
      textBytes = console.next().getBytes();
   
      try {
         pubKeyBytes = Files.readAllBytes(Paths.get(pubKeyFile));
         pubKey = pointFromBytes(pubKeyBytes);
         eGram = encryptByteArray(textBytes, pubKey);
         cText = new BigInteger(1, eGram.cryptogram)
               .toString(16)
               .toUpperCase();
         
         STDOUT.printf("Hexadecimal Ciphertext: %s\n", cText);
         
         // to get a printable hex value
         saltVal = new BigInteger(1, eGram.zPt.toByteArray())
               .toString(16)
               .toUpperCase();
         tagVal = new BigInteger(1, eGram.authTag)
               .toString(16)
               .toUpperCase();
         STDOUT.printf(
               "Your \"salt\" is: %s\nYour authentication tag is: %s\n", saltVal, tagVal
         );
         askExit(console);
      } catch (IOException ioe) {
         STDOUT.print("IO Error: Couldn't get the public key file. ");
         if (askRetry(console)) encryptTextElliptic(console);
         else askExit(console);
      }
   }
   
   /**
    * Provides prompts and interactivity for decryption of text input by the user.
    * NOT FULLY STABLE. MAY CRASH.
    * @param console one Scanner to scan them all
    */
   private static void decryptTextElliptic(Scanner console) {
      byte[] cTextBytes, decryptedBytes;
      BigInteger saltNum, tagNum;
      String saltVal, tagVal, cText, passPhrase;
      ElliptiCryptogram eGram;
   
      STDOUT.println("Elliptic Text Decryption using passphrase");
   
      STDOUT.print("Hexadecimal Cryptogram to be decrypted?: ");
      cText = console.next();
   
      STDOUT.print("Passphrase?: ");
      passPhrase = console.next();
   
      STDOUT.print("\"Salt\"?: ");
      saltVal = console.next();
   
      STDOUT.print("Auth Tag?: ");
      tagVal = console.next();
   
      saltNum = new BigInteger(saltVal, 16);
      tagNum = new BigInteger(tagVal, 16);
      cTextBytes = new BigInteger(cText, 16).toByteArray();
      
      eGram = new ElliptiCryptogram(
            pointFromBytes(saltNum.toByteArray()),
            cTextBytes,
            tagNum.toByteArray()
      );
      
      decryptedBytes = deCryptogram(eGram, passPhrase.getBytes());
   
      // if authentication fails, deCryptogram returns null instead of bytes
      if (Objects.nonNull(decryptedBytes)) {
         STDOUT.printf("Decrypted Message: %s\n", new String(decryptedBytes));
      } else {
         STDOUT.println("Authentication failed. Could not decrypt.");
      }
      askExit(console);
   }
   
   
   private static void encryptAndSignFile(Scanner console) {
      //file to encrypt/sign
      //recipient's public key file
      //user's private key file
      //password to decrypt private key file
      
      //retrieve private key
      //generate signature
      //encrypt
      //output all files
      byte[] fileBytes, privKeyBytes, privKeyPwBytes;
      E521Point pubKey;
      ECKeyPair keys;
      ElliptiCryptogram eGram;
      DigitalSignature sig;
      String fileName;
      Path pubKeyFilePath, privKeyFilePath;
      STDOUT.println("Encrypt-n'-Sign:");
      STDOUT.println("Sign a file with your private key, then encrypt it under a " +
            "recipient's public key.\n");
      
      STDOUT.print("Name of file to be signed and encrypted?: ");
      fileName = console.next();
      
      STDOUT.print("Name of the recipient's public key file?: ");
      pubKeyFilePath = Paths.get(console.next());
      
      
      STDOUT.print("Passphrase for the private key?: ");
      privKeyPwBytes = console.next().getBytes();
      
      
      //retrieve private key bytes
      keys = generateKeyPair(privKeyPwBytes);
      
      //to be continued....
   }
   
   
   
   
   
   
   
   
   
   
   private static void askExit(Scanner console) {
      STDOUT.print("\nExit program? (y/n): ");
      if (detectYes(console.next())) quit(console);
   }
   
   private static boolean askRetry(Scanner console) {
      STDOUT.print("Retry? (y/n/q): ");
      String in = console.next();
      if (detectQuit(in)) quit(console);
      return detectYes(in);
   }
   
   private static boolean detectQuit(String input) {
      return
            input.equalsIgnoreCase("q") ||
                  input.equalsIgnoreCase("quit");
   }
   
   private static boolean detectYes(String in) {
      return
            in.equalsIgnoreCase("y") ||
                  in.equalsIgnoreCase("yes");
   }
   
   /**
    * Closes Scanner and quits program.
    * @param console one Scanner to scan them all (not for much longer)
    */
   private static void quit(Scanner console) {
      console.close();
      System.exit(0);
   }
   
   
////////////////////////////////////////////////////////////////// Main Application //////
///////////////////////////////////// Cryptographic Hashing/Symmetric/Auth Services //////
   
   
   /**
    * Generates a cryptographic hash of a byte array.
    * @param m bytes to be hashed
    * @return byte array of the digest
    */
   private static byte[] hashByteArray(byte[] m) {
      return HashLib.KMACXOF256("".getBytes(), m, 512 / 8, "D");
   }
   
   /**
    * Generates an authentication tag for a byte array under a given passphrase.
    * @param m message bytes for which an auth tag is needed
    * @param pw passphrase for authentication
    * @return MAC tag
    */
   private static byte[] authTag(byte[] m, byte[] pw) {
      return HashLib.KMACXOF256(pw, m, 512 / 8, "T");
   }
   
   /**
    * Encrypts a byte array symmetrically under a given passphrase.
    * @param m message bytes to be encrypted
    * @param pw passphrase for encryption/decryption
    * @return container object with the salt, cryptogram, and auth tag inside
    */
   private static SymmetriCryptogram encryptByteArray(byte[] m, byte[] pw) {
      byte[] rBytes, saltedPW, keka, ke, ka, cMask, cGram, aTag;
      
      // get 64 random bytes and salt the passphrase
      rBytes = new byte[512 / 8];
      myRand.nextBytes(rBytes);
      saltedPW = ArrayUtils.mergeByteArrays(rBytes, pw);
      
      // get ke and ka for cryptogram and tag generation
      keka = HashLib.KMACXOF256(saltedPW, "".getBytes(), 1024 / 8, "S");
      ke = Arrays.copyOf(keka, 512 / 8);
      ka = Arrays.copyOfRange(keka, 512 / 8, 1024 / 8);
      
      // generate cryptogram and tag
      cMask = HashLib.KMACXOF256(ke, "".getBytes(), m.length, "SKE");
      cGram = ArrayUtils.byteArrayXOR(m, cMask);
      aTag = HashLib.KMACXOF256(ka, m, 512 / 8, "SKA");
      
      return new SymmetriCryptogram(rBytes, cGram, aTag);
   }
   
   /**
    * Given: a container object with the salt, cryptogram, and auth tag; and a passphrase,
    * attempts decryption and tag verification.
    * @param cGram container object with salt, cryptogram, and auth tag
    * @param pwBytes passphrase for decryption as bytes
    * @return byte array of decrypted message, or null if authentication fails
    */
   private static byte[] deCryptogram(SymmetriCryptogram cGram, byte[] pwBytes) {
      byte[] saltedPWBytes, keka, ke, ka, dMaskBytes, decryptedM, tagCandBytes;
      
      // retrieve salt and add to pw
      saltedPWBytes = ArrayUtils.mergeByteArrays(cGram.z, pwBytes);
      
      // generate ke and ka
      keka = HashLib.KMACXOF256(saltedPWBytes, "".getBytes(), 1024 / 8, "S");
      ke = Arrays.copyOf(keka, 512 / 8);
      ka = Arrays.copyOfRange(keka, 512 / 8, 1024 / 8);
      
      // decrypt
      dMaskBytes = HashLib.KMACXOF256(ke, "".getBytes(), cGram.cryptogram.length, "SKE");
      decryptedM = ArrayUtils.byteArrayXOR(cGram.cryptogram, dMaskBytes);
      
      // generate tag candidate for verification
      tagCandBytes = HashLib.KMACXOF256(ka, decryptedM, 512 / 8, "SKA");
      
      return ArrayUtils.byteArrayEquals(cGram.authTag, tagCandBytes)?
            decryptedM : null;
   }
   
   
///////////////////////////////////// Cryptographic Hashing/Symmetric/Auth Services //////
////////////////////////////////////////////// Elliptic Curve Cryptography Services //////
   
   
   /**
    * Generates an elliptic curve key pair given the bytes of the password.
    * @param pwBytes password bytes
    * @return container object with key pair data
    */
   private static ECKeyPair generateKeyPair(byte[] pwBytes) {
      byte[] privKeyBytes;
      BigInteger scalar;
      E521Point pubKeyV;
   
      if (Objects.isNull(pwBytes) || pwBytes.length == 0) {
         pwBytes = new byte[64];
         myRand.nextBytes(pwBytes);
      }
      
      scalar = new BigInteger(1, HashLib.KMACXOF256(pwBytes, "".getBytes(), 512 / 8, "K"));
      scalar = scalar.multiply(BigInteger.valueOf(4));
      privKeyBytes = scalar.toByteArray();
      
      pubKeyV = E521CurveLib.constructGenerator().scalarMultiply(scalar);
      return new ECKeyPair(privKeyBytes, pubKeyV);
   }
   
   /**
    * Encrypts a byte array under a given public key
    * @param m message bytes to be encrypted
    * @param pubKey point object representing public key
    * @return encrypted data and supporting tokens in container
    */
   private static ElliptiCryptogram encryptByteArray(final byte[] m, final E521Point pubKey) {
      byte[] rBytes, workingXBytes, keka, ke, ka,cMaskBytes, cGramBytes, aTagBytes;
      BigInteger k, workingX;
      E521Point working, rand;
      
      // get 64 random bytes and "salt the key"
      rBytes = new byte[64];
      myRand.nextBytes(rBytes);
      k = new BigInteger(1, rBytes).multiply(FOUR).mod(P521);
      working = pubKey.scalarMultiply(k);
      rand = constructGenerator().scalarMultiply(k);
      
      // prepare Wx, x-coord of the working point
      workingX = working.xCoord();
      workingXBytes = workingX.toByteArray();
      
      // generate ke and ka
      keka = HashLib.KMACXOF256(workingXBytes, "".getBytes(), 1024 / 8, "P");
      ke = Arrays.copyOfRange(keka, 0, 512 / 8);
      ka = Arrays.copyOfRange(keka, 512 / 8, 1024 / 8);
      
      // generate mask, cryptogram and tag
      cMaskBytes = HashLib.KMACXOF256(ke, "".getBytes(), m.length, "PKE");
      cGramBytes = ArrayUtils.byteArrayXOR(m, cMaskBytes);
      aTagBytes = HashLib.KMACXOF256(ka, m, 512 / 8, "PKA");
      
      return new ElliptiCryptogram(rand, cGramBytes, aTagBytes);
   }
   
   /**
    * Given: a container object with the salt, cryptogram, and auth tag; and a passphrase,
    * attempts decryption and tag verification.
    * @param eGram container object with "salt point", cryptogram, and auth tag
    * @param pwBytes passphrase for decryption as bytes
    * @return byte array of decrypted message, or null if authentication fails
    */
   public static byte[] deCryptogram(final ElliptiCryptogram eGram, final byte[] pwBytes) {
      byte[] scalarBytes, workingXBytes, keka, ke, ka, dMaskBytes, decryptedM, tagCandBytes;
      BigInteger four = BigInteger.valueOf(4), scalar, workingX;
      E521Point workingPt;
   
      scalarBytes = HashLib.KMACXOF256(pwBytes, "".getBytes(), 512 / 8, "K");
      scalar = new BigInteger(1, scalarBytes)
            .multiply(four).mod(P521);
      workingPt = eGram.zPt.scalarMultiply(scalar);
      workingX = workingPt.xCoord();
      workingXBytes = workingX.toByteArray();
      
      // generate ke and ka
      keka = HashLib.KMACXOF256(workingXBytes, "".getBytes(), 1024 / 8, "P");
      ke = Arrays.copyOf(keka, 512 / 8);
      ka = Arrays.copyOfRange(keka, 512 / 8, 1024 / 8);
   
      // decrypt
      dMaskBytes = HashLib.KMACXOF256(ke, "".getBytes(), eGram.cryptogram.length, "PKE");
      decryptedM = ArrayUtils.byteArrayXOR(eGram.cryptogram, dMaskBytes);
   
      // generate tag candidate for verification
      tagCandBytes = HashLib.KMACXOF256(ka, decryptedM, 512 / 8, "PKA");
      
      return ArrayUtils.byteArrayEquals(eGram.authTag, tagCandBytes)?
            decryptedM : null;
   }
   
   /**
    * Generates a digital signature for a file given its bytes and the bytes of the
    * passphrase being used for encryption.
    * @param m bytes of file being signed
    * @param pwBytes bytes of password for signature
    * @return container object with signature data
    */
   public static DigitalSignature signByteArray(final byte[] m, final byte[] pwBytes) {
      byte[] sBytes, uXBytes, hBytes;
      BigInteger scalar, k, uX, hashVal, z;
      E521Point uPt;
   
      scalar = new BigInteger(1, HashLib.KMACXOF256(pwBytes, "".getBytes(), 512 / 8, "K"));
      sBytes = scalar.multiply(FOUR).toByteArray(); // s <- 4s
   
      k = new BigInteger(1, HashLib.KMACXOF256(sBytes, m, 512 / 8, "N"));
      k = k.multiply(FOUR); // k <- 4k
      
      uPt = constructGenerator().scalarMultiply(k); // u <- k * G
      uX = uPt.xCoord();
      uXBytes = uX.toByteArray();
      
      hBytes = HashLib.KMACXOF256(uXBytes, m, 512 / 8, "T");
      hashVal = new BigInteger(1, hBytes);
      
      z = k.subtract(hashVal.multiply(scalar)).mod(R521);
      
      return new DigitalSignature(hashVal, z);
   }
   
   /**
    * Attempts to verify a file and its signature under PKI.
    * @param theSig container object with signature data
    * @param m bytes of the file being verified
    * @param thePubKey point object representing the public key
    * @return whether authentication succeeded
    */
   public static boolean verifySignature(
         final DigitalSignature theSig,
         final byte[] m,
         final E521Point thePubKey
   ) {
      byte[] uXBytes, hCandBytes;
      BigInteger hCand, uX;
      E521Point zPt, hPt, uPt;
      
      zPt = constructGenerator().scalarMultiply(theSig.zVal);
      hPt = thePubKey.scalarMultiply(theSig.hashVal);
      uPt = zPt.curvePtAdd(hPt);
   
   
      uX = uPt.xCoord();
      uXBytes = uX.toByteArray();
      
      hCandBytes = HashLib.KMACXOF256(uXBytes, m, 512 / 8, "T");
      hCand = new BigInteger(1, hCandBytes);
      
      return hCand.equals(theSig.hashVal);
   }
   
   
////////////////////////////////////////////// Elliptic Curve Cryptography Services //////
///////////////////////////////////////////////////////////////// Container Classes //////
   
   
   /**
    * Container class for an elliptic curve key pair.
    */
   private static class ECKeyPair {
      private final byte[] myPrivKeyBytes;
      private final E521Point myPublicKey;
      
      private ECKeyPair(byte[] privKeyBytes, E521Point pubKeyPt) {
         this.myPrivKeyBytes = privKeyBytes;
         this.myPublicKey = pubKeyPt;
      }
   }
   
   /**
    * Container class for elliptic cryptogram data.
    */
   private static class ElliptiCryptogram {
      private final E521Point zPt;
      private final byte[] cryptogram;
      private final byte[] authTag;
      
      ElliptiCryptogram(final E521Point randPoint, final byte[] cGram, final byte[] tag) {
         zPt = randPoint;
         cryptogram = cGram;
         authTag = tag;
      }
   }
   
   /**
    * Container class for symmetric cryptogram data.
    */
   private static class SymmetriCryptogram {
      private final byte[] z;
      private final byte[] cryptogram;
      private final byte[] authTag;
      
      SymmetriCryptogram(byte[] randBytes, byte[] cGram, byte[] tag) {
         z = randBytes;
         cryptogram = cGram;
         authTag = tag;
         
      }
   }
   
   /**
    * Container class for signature data.
    */
   private static class DigitalSignature {
      private final BigInteger hashVal;
      private final BigInteger zVal;
      
      DigitalSignature(final BigInteger candHash, final BigInteger candZ) {
         hashVal = candHash;
         zVal = candZ;
      }
      
      public void toFile(Path filePath) throws IOException {
         byte[] fileBytes = ArrayUtils.mergeByteArrays(
               hashVal.toByteArray(),
               zVal.toByteArray()
         );
         Files.write(filePath,fileBytes);
      }
      
      public static DigitalSignature fromFile(Path filePath) throws IOException {
         byte[] fileBytes = Files.readAllBytes(filePath);
         
         // hash val should the first 64 bytes of the signature file
         byte[] hashValBytes = Arrays.copyOfRange(fileBytes, 0, 64);
         byte[] zValBytes = Arrays.copyOfRange(fileBytes, 64, fileBytes.length);
         
         return new DigitalSignature(new BigInteger(hashValBytes), new BigInteger(zValBytes));
      }
   }
}
