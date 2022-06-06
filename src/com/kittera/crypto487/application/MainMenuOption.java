package com.kittera.crypto487.application;

public enum MainMenuOption {
   HASHFILE(1,"Plain cryptographic hash of a file"),
   HASHTEXT(2, "Plain cryptographic hash of text input"),
   SYMMENC(3, "Symmetric Encryption of given file w/ given passphrase"),
   SYMMDEC(4, "Symmetric Decryption of given file w/ salt, cryptogram, tag and passphrase"),
   AUTHTAG(5, "Generate a MAC for a file w/ given passphrase"),
   GENKEYPAIR(6, "Generate an ECDHIES key pair from a given passphrase, write public key to file"), // TODO and optionally...
   ELLIPTENC(7, "Elliptic encryption of given file w/ given public key"),
   ELLIPTDEC(8, "Elliptic decryption of elliptically-encrypted file"),
   ELLIPTTEXTENC(9, "Elliptic encryption of text input w/ given public key"),
   ELLIPTTEXTDEC(10, "Elliptic decryption of elliptically-encrypted text input"),
   SIGNFILE(11, "Sign a given file under a given passphrase"),
   VERIFYSIG(12, "Verify a file signature"),
   CRYPTENVEL(13, "Encrypt and sign a file for sending"),
   QUIT(14, "Quit Program");
   
   public final int optionNumber;
   
   public final String promptString;
   
   MainMenuOption(final int optionNum, final String prompt) {
      optionNumber = optionNum;
      promptString = prompt;
   }
}
