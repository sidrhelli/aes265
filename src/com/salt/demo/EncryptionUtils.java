package com.salt.demo;

public class EncryptionUtils {


  public static void main(String[] args) throws Exception {

    if (args.length == 2) {

      if (args[0].equals("encrypt") && null != args[1]) {
        System.out.println("output: " + Aes.encrypt(args[1]));

      } else if (args[0].equals("decrypt") && null != args[1]) {
        System.out.println("output: " + Aes.decrypt(args[1]));

      }
    } else {
      throw new IllegalArgumentException();
    }

  }

}
