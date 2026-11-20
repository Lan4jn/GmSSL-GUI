package org.gmssl.gui.platform;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionTemplate;

class CredentialValidationTest {
  @Test
  void rejectsOversizeUtf8AndLineControlsBeforePersistence() {
    Store store = mock(Store.class);
    Vault vault = mock(Vault.class);
    CredentialService service = new CredentialService(store, vault, mock(TransactionTemplate.class));
    for (String pass : new String[] {"密".repeat(171), "a\rb", "a\nb", "a\0b"}) {
      assertThrows(ApiError.class, () -> service.savePassphrase("project", "material", pass));
    }
    verifyNoInteractions(vault, store);
  }

  @Test
  void acceptsExactly512Utf8Bytes() {
    CredentialService service = new CredentialService(mock(Store.class), mock(Vault.class), mock(TransactionTemplate.class));
    assertDoesNotThrow(() -> service.savePassphrase("project", "material", "密".repeat(170) + "ab"));
    assertDoesNotThrow(() -> service.savePassphrase("project", "material", "a".repeat(512)));
  }
}
