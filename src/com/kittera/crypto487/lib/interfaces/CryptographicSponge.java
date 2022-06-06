package com.kittera.crypto487.lib.interfaces;

public interface CryptographicSponge {
   void absorbAll(byte[] x);
   byte[] squeeze();
}
