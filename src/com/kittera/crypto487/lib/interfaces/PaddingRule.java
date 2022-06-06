package com.kittera.crypto487.lib.interfaces;

public interface PaddingRule {
   byte[] apply(byte[] in, int rateInBits);
}
