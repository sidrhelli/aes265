package com.salt.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.Test;

public class AesTest {

  @Test
  public void shouldecryptCipherText() throws Exception {
    assertEquals("dit is plain text", Aes.decrypt("pCyLKWz0YdfjSPm7WUw4J1zbznFV9iIQy0CB1QU1zyvsetLQNF2rQ0G68BTSme66"));
  }
}
