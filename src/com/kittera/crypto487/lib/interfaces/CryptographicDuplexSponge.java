package com.kittera.crypto487.lib.interfaces;

public interface CryptographicDuplexSponge extends CryptographicSponge {
   byte[] duplexAbsorb(byte[] x);
}
