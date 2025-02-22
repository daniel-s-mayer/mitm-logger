// From: https://github.com/zozs/openssl-sign-by-ca/blob/master/openssl1.1/main.c

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "proxy.h"

#define RSA_KEY_BITS (4096)

#define REQ_DN_C "SE"
#define REQ_DN_ST ""
#define REQ_DN_L ""
#define REQ_DN_O "Example Company"
#define REQ_DN_OU ""
#define REQ_DN_CN "VNF Application"
#define ALT_NAM ""

// MUTEX for protecting existence and certificate file creation checks.
pthread_mutex_t cert_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t key_mutex = PTHREAD_MUTEX_INITIALIZER;

static void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size);
static int generate_key_csr(EVP_PKEY **key, X509_REQ **req, char* cert_domain);
static int generate_set_random_serial(X509 *crt);
static int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt, char* cert_domain);
static void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size);
static int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt);
static void store_key(uint8_t* key, size_t key_length, char* cert_domain);
static void store_cert(uint8_t* key, size_t key_length, char* cert_domain);

// May want to make the generator return instantly if a cert already exists for the domain.
// Check about expiration dates etc.
int generate_cert(char* ca_key_path, char* ca_crt_path, char* cert_domain) {
	// Nullity pre-checks
	if (ca_key_path == NULL || ca_crt_path == NULL || cert_domain == NULL) {
		return -1;
	}
    // Check if both the cert and key files already exist. 
    char* composite_cert_filename = Calloc(strlen(cert_domain) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -crt.pem
    strcpy(composite_cert_filename, CERTS_DIRECTORY);
	strcat(composite_cert_filename, cert_domain);
    strcat(composite_cert_filename, "-crt.pem");
    char* composite_key_filename = Calloc(strlen(cert_domain) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -key.pem
    strcpy(composite_key_filename, CERTS_DIRECTORY);
	strcat(composite_key_filename, cert_domain);
    strcat(composite_key_filename, "-key.pem");
	pthread_mutex_lock(&key_mutex);
	pthread_mutex_lock(&cert_mutex);
    if (access(composite_cert_filename, F_OK) == 0 && access(composite_key_filename, F_OK) == 0) {
        pthread_mutex_unlock(&cert_mutex);
		pthread_mutex_unlock(&key_mutex);
		free(composite_cert_filename);
		free(composite_key_filename);
		return 0; // The cert has already been generated! Think later about dates. 
    } 
	pthread_mutex_unlock(&cert_mutex);
	pthread_mutex_unlock(&key_mutex);

	/* Load CA key and cert. */
	EVP_PKEY *ca_key = NULL;
	X509 *ca_crt = NULL;
	if (!load_ca(ca_key_path, &ca_key, ca_crt_path, &ca_crt)) {
		fprintf(stderr, "Failed to load CA certificate and/or key!\n");
		return 1;
	}

	/* Generate keypair and then print it byte-by-byte for demo purposes. */
	EVP_PKEY *key = NULL;
	X509 *crt = NULL;

	int ret = generate_signed_key_pair(ca_key, ca_crt, &key, &crt, cert_domain);
	if (!ret) {
		fprintf(stderr, "Failed to generate key pair!\n");
		return 1;
	}
	/* Convert key and certificate to PEM format. */
	uint8_t *key_bytes = NULL;
	uint8_t *crt_bytes = NULL;
	size_t key_size = 0;
	size_t crt_size = 0;

	key_to_pem(key, &key_bytes, &key_size);
	crt_to_pem(crt, &crt_bytes, &crt_size);

	/* Print key and certificate. */
	store_key(key_bytes, key_size, cert_domain);
	store_cert(crt_bytes, crt_size, cert_domain);

	/* Free stuff. */
	EVP_PKEY_free(ca_key);
	EVP_PKEY_free(key);
	X509_free(ca_crt);
	X509_free(crt);
	free(key_bytes);
	free(crt_bytes);
	free(composite_cert_filename);
	free(composite_key_filename);

	return 0;
}

void crt_to_pem(X509 *crt, uint8_t **crt_bytes, size_t *crt_size)
{
	/* Convert signed certificate to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, crt);
	*crt_size = BIO_pending(bio);
	*crt_bytes = (uint8_t *)malloc(*crt_size + 1);
	BIO_read(bio, *crt_bytes, *crt_size);
	BIO_free_all(bio);
}

int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ext;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) {
        return 0;
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return 1;
}

int generate_signed_key_pair(EVP_PKEY *ca_key, X509 *ca_crt, EVP_PKEY **key, X509 **crt, char* cert_domain)
{
	/* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!generate_key_csr(key, &req, cert_domain)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)25*365*24*3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    

    // Add the cert domain to the subject alt name.
    char* subject_alt_name = calloc(strlen(ALT_NAM) + 9 + strlen(cert_domain), sizeof(char));
    strcpy(subject_alt_name, ALT_NAM);
    strcat(subject_alt_name, "DNS:");
    strcat(subject_alt_name, cert_domain);

	add_ext(*crt, NID_subject_alt_name, subject_alt_name);

	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int generate_key_csr(EVP_PKEY **key, X509_REQ **req, char* cert_domain)
{
	*key = NULL;
	*req = NULL;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;

	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;
	rsa = RSA_new();
	if (!rsa) goto err;
	e = BN_new();
	if (!e) goto err;

	BN_set_word(e, 65537);
	if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) goto err;
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	X509_NAME *name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cert_domain, -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;

	BN_free(e);

	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	RSA_free(rsa);
	BN_free(e);
	return 0;
}

int generate_set_random_serial(X509 *crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

void key_to_pem(EVP_PKEY *key, uint8_t **key_bytes, size_t *key_size)
{
	/* Convert private key to PEM format. */
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
	*key_size = BIO_pending(bio);
	*key_bytes = (uint8_t *)malloc(*key_size + 1);
	BIO_read(bio, *key_bytes, *key_size);
	BIO_free_all(bio);
}

int load_ca(const char *ca_key_path, EVP_PKEY **ca_key, const char *ca_crt_path, X509 **ca_crt)
{
	BIO *bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}



void store_key(uint8_t *key, size_t key_length, char* cert_domain)
{
	pthread_mutex_lock(&key_mutex);
    char* composite_filename = Calloc(strlen(cert_domain) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -key.pem
    strcpy(composite_filename, CERTS_DIRECTORY);
	strcat(composite_filename, cert_domain);
    strcat(composite_filename, "-key.pem");
    FILE* key_file = fopen(composite_filename, "w");
	for (size_t i = 0; i < key_length; i++) {
		fprintf(key_file, "%c", key[i]);
	}
	free(composite_filename);
    fclose(key_file);
	pthread_mutex_unlock(&key_mutex);
}

void store_cert(uint8_t *cert, size_t key_length, char* cert_domain)
{
	pthread_mutex_lock(&cert_mutex);
    char* composite_filename = calloc(strlen(cert_domain) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -crt.pem
    strcpy(composite_filename, CERTS_DIRECTORY);
	strcat(composite_filename, cert_domain);
    strcat(composite_filename, "-crt.pem");
    FILE* key_file = fopen(composite_filename, "w");
	for (size_t i = 0; i < key_length; i++) {
		fprintf(key_file, "%c", cert[i]);
	}
	free(composite_filename);
    fclose(key_file);
	pthread_mutex_unlock(&cert_mutex);
}

/*
int main() {
    // A demo main function.
    generate_cert("myCA.pem", "myCA.crt", "mayer-studios.com");
}
*/