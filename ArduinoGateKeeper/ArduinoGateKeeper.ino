#define LED_Red 2
#define LED_Green 3
#define BUZZER 4

void setup() {
  // put your setup code here, to run once:
  pinMode(LED_Red, OUTPUT);
  pinMode(LED_Green, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  grantAccess();
  denyAccess();

}

void grantAccess() {
  digitalWrite(LED_Green, HIGH);
  digitalWrite(BUZZER, HIGH);
  delay(500);
  digitalWrite(BUZZER, LOW);
  delay(4500);
  digitalWrite(LED_Green, LOW);
}

void denyAccess() {
  digitalWrite(LED_Red, HIGH);
  delay(5000);
  digitalWrite(LED_Red, LOW);
}

void loop() {
  // put your main code here, to run repeatedly:

}
