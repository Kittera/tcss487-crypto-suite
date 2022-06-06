package com.kittera.crypto487.lib.interfaces;

public interface PermutationFunction {
   
   /**
    * Function to be used in the update phase of the sponge construction
    * @param inputState input byte array to be permuted
    * @return a new byte array representing the permutation of the given byte array
    */
   byte[] apply(byte[] inputState);
}

