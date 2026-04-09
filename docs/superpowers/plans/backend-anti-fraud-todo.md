# Backend Anti-Fraud: Remaining Changes (monclub_backend)

Java repo was not present on this machine. Apply these changes in `monclub_backend`.

---

## 1. `GymDevice.java` — add 3 JPA columns

Find the entity class (search for `@Entity` + `class GymDevice`).
Add alongside `totpEnabled`, `rfidEnabled`:

```java
@Column(name = "anti_fraude_card", nullable = false)
private boolean antiFraudeCard = true;

@Column(name = "anti_fraude_qr_code", nullable = false)
private boolean antiFraudeQrCode = true;

@Column(name = "anti_fraude_duration", nullable = false)
private int antiFraudeDuration = 30;
```

Add getters/setters (or Lombok `@Getter @Setter` if already used):

```java
public boolean isAntiFraudeCard() { return antiFraudeCard; }
public void setAntiFraudeCard(boolean v) { this.antiFraudeCard = v; }

public boolean isAntiFraudeQrCode() { return antiFraudeQrCode; }
public void setAntiFraudeQrCode(boolean v) { this.antiFraudeQrCode = v; }

public int getAntiFraudeDuration() { return antiFraudeDuration; }
public void setAntiFraudeDuration(int v) { this.antiFraudeDuration = v; }
```

---

## 2. `GymDeviceDto.java` — add 3 DTO fields

```java
private boolean antiFraudeCard = true;
private boolean antiFraudeQrCode = true;
private int antiFraudeDuration = 30;
```

---

## 3. `GymAccessController.java` — map fields in `get_gym_users` builder

Find the devices list builder (search for `.totpEnabled(` in the devices mapping).
Add next to it:

```java
.antiFraudeCard(device.isAntiFraudeCard())
.antiFraudeQrCode(device.isAntiFraudeQrCode())
.antiFraudeDuration(device.getAntiFraudeDuration())
```

---

## 4. DB migration

Create the next migration file (Flyway/Liquibase — check the existing V*.sql files for numbering):

```sql
ALTER TABLE gym_device
    ADD COLUMN anti_fraude_card     BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_qr_code  BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN anti_fraude_duration INTEGER NOT NULL DEFAULT 30;
```

---

## 5. Verify

```bash
./mvnw test -Dtest="GymDevice*,GymAccess*"
```

Expected: BUILD SUCCESS. Existing devices automatically get defaults (true, true, 30).
