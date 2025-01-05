#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "ascon.h"  // Ascon şifreleme fonksiyonlarını dahil et
#include "ascon.c" 

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

// Anahtar ve nonce (Ascon şifreleme için)
static uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};  // 16-byte key
static uint8_t nonce[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};  // 16-byte nonce

static struct simple_udp_connection udp_conn;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  uint8_t decrypted_data[64];  // Gelen mesajı çözmek için tampon
  if (datalen > sizeof(decrypted_data)) {
    LOG_ERR("Received data is too large to decrypt\n");
    return;
  }

  // Gelen mesajı kopyala ve çöz
  memcpy(decrypted_data, data, datalen);
  
  // Ascon şifre çözme işlemi
  ascon_decrypt(decrypted_data, data, datalen, key, nonce);
  decrypted_data[datalen] = '\0'; // Null-terminate for safety

  // Çözülen mesajı logla
  LOG_INFO("Received decrypted message: '%s' from ", decrypted_data);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

#if WITH_SERVER_REPLY
  /* Cevap olarak şifrelenmiş mesajı geri gönder */
  LOG_INFO("Sending encrypted response back\n");
  
  // Ascon şifreleme işlemi
  uint8_t encrypted_response[64];
  const char *response = "Response from server";
  size_t response_len = strlen(response);
  
  // Şifrele ve geri gönder
  ascon_encrypt(encrypted_response, (uint8_t *)response, response_len, key, nonce);
  simple_udp_sendto(&udp_conn, encrypted_response, response_len, sender_addr);
#endif /* WITH_SERVER_REPLY */
}

PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  /* Initialize DAG root */
  NETSTACK_ROUTING.root_start();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);

  PROCESS_END();
}