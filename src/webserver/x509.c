/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  X.509 certificate and randomness generator routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "x509.h"

#ifdef HAVE_GNUTLS
# include <gnutls/abstract.h>
# include <gnutls/crypto.h>
# include <gnutls/gnutls.h>
# include <nettle/sha1.h>

// We enforce at least GnuTLS v3.4.0 if we use it
#if GNUTLS_VERSION_NUMBER < 0x030400
# error "GnuTLS version 3.4.0 or later is required"
#endif

#define GTLS_CHECK_GOTO(stmt, label) do { rc = stmt; if(rc != GNUTLS_E_SUCCESS) goto label; } while(false)
#define GTLS_CHECK(stmt) GTLS_CHECK_GOTO(stmt, clean)

#define RSA_KEY_SIZE 4096
#define BUFFER_SIZE 16000

// Generate private EC or RSA key
static int generate_keypair(gnutls_x509_privkey_t privkey,
                            gnutls_pubkey_t pubkey,
							gnutls_pk_algorithm_t type,
							unsigned int bits,
                            gnutls_datum_t *key_buffer)
{
	int rc;

	// Generate private key.
	GTLS_CHECK(gnutls_x509_privkey_generate(privkey, type, bits, 0));

	// Extract the public key.
	gnutls_privkey_t pk = NULL;

	GTLS_CHECK(gnutls_privkey_init(&pk));
	GTLS_CHECK(gnutls_privkey_import_x509(pk, privkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE));
	GTLS_CHECK(gnutls_pubkey_import_privkey(pubkey, pk, 0, 0));
	// Don't call gnutls_privkey_deinit(), as this is pointing to the original X509 private key

	// Export key in PEM format
	return gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, key_buffer);

clean:
	return rc;
}

// Write a key and/or certificate to a file
static bool write_to_file(const char *filename, const char *type, const char *suffix, const char *cert, const char *key)
{
	// Create file with CA certificate only
	char *targetname = calloc(strlen(filename) + (suffix != NULL ? strlen(suffix) : 0) + 1, sizeof(char));
	strcpy(targetname, filename);

	if(suffix != NULL)
	{
		// If the certificate file name ends with ".pem", replace it
		// with the specified suffix. Otherwise, append the specified
		// suffix to the certificate file name
		if (strlen(targetname) > 4 && strcmp(targetname + strlen(targetname) - 4, ".pem") == 0)
			targetname[strlen(filename) - 4] = '\0';

		strcat(targetname, suffix);
	}

	printf("Storing %s in %s ...\n", type, targetname);
	FILE *f = NULL;
	if ((f = fopen(targetname, "wb")) == NULL)
	{
		printf("ERROR: Could not open %s for writing\n", targetname);
		return false;
	}

	// Restrict permissions to owner read/write only
	if(fchmod(fileno(f), S_IRUSR | S_IWUSR) != 0)
		log_warn("Unable to set permissions on file \"%s\": %s", targetname, strerror(errno));

	// Write key (if provided)
	if(key != NULL)
	{
		const size_t olen = strlen((char *) key);
		if (fwrite(key, 1, olen, f) != olen)
		{
			printf("ERROR: Could not write key to %s\n", targetname);
			fclose(f);
			return false;
		}
	}

	// Write certificate (if provided)
	if(cert != NULL)
	{
		const size_t olen = strlen((char *) cert);
		if (fwrite(cert, 1, olen, f) != olen)
		{
			printf("ERROR: Could not write certificate to %s\n", targetname);
			fclose(f);
			return false;
		}
	}

	// Close cert file
	fclose(f);
	free(targetname);

	return true;
}

bool generate_certificate(const char* certfile, bool rsa, const char *domain)
{
	int rc;
	bool res = false;
	gnutls_x509_crt_t ca_crt = NULL, srv_crt = NULL;
	gnutls_x509_privkey_t ca_privkey = NULL, srv_privkey = NULL;
	gnutls_pubkey_t ca_pubkey = NULL, srv_pubkey = NULL;
	char *subject_name = NULL;
	gnutls_datum_t ca_crt_buffer = { NULL, 0 };
	gnutls_datum_t ca_key_buffer = { NULL, 0 };
	gnutls_datum_t srv_crt_buffer = { NULL, 0 };
	gnutls_datum_t srv_key_buffer = { NULL, 0 };

	// Initialize structures
	GTLS_CHECK(gnutls_x509_crt_init(&ca_crt));
	GTLS_CHECK(gnutls_x509_crt_init(&srv_crt));
	GTLS_CHECK(gnutls_x509_privkey_init(&ca_privkey));
	GTLS_CHECK(gnutls_x509_privkey_init(&srv_privkey));
	GTLS_CHECK(gnutls_pubkey_init(&ca_pubkey));
	GTLS_CHECK(gnutls_pubkey_init(&srv_pubkey));

	// Generate key pair
	printf("Generating %s key...\n", rsa ? "RSA" : "EC");
	if((rc = generate_keypair(ca_privkey, ca_pubkey,
	                          rsa ? GNUTLS_PK_RSA : GNUTLS_PK_ECDSA, 
	                          rsa ? 4096 : GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1),
	                          &ca_key_buffer)) != GNUTLS_E_SUCCESS)
	{
		printf("ERROR: generate_keypair returned %d\n", rc);
		goto clean;
	}
	if((rc = generate_keypair(srv_privkey, srv_pubkey,
	                          rsa ? GNUTLS_PK_RSA : GNUTLS_PK_ECDSA, 
	                          rsa ? 4096 : GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1),
	                          &srv_key_buffer)) != GNUTLS_E_SUCCESS)
	{
		printf("ERROR: generate_keypair returned %d\n", rc);
		goto clean;
	}

	// Create string with random digits for unique serial number
	// RFC 2459: The serial number is an integer assigned by the CA to each
	// certificate. It MUST be unique for each certificate issued by a given
	// CA (i.e., the issuer name and serial number identify a unique
	// certificate).
	// We generate a random string of 16 digits, which should be unique enough
	// for our purposes. We use the same random number generator as for the
	// key generation to ensure that the serial number is not predictable.
	// The serial number could be a constant, e.g., 1, but this would allow
	// only one certificate being issued with a given browser. Any new generated
	// certificate would be rejected by the browser as it would have the same
	// serial number as the previous one and uniques is violated.
	unsigned char serial1[16] = { 0 }, serial2[16] = { 0 };
	GTLS_CHECK(gnutls_rnd(GNUTLS_RND_KEY, serial1, sizeof(serial1)));
	for(unsigned int i = 0; i < sizeof(serial1) - 1; i++)
		serial1[i] = '0' + (serial1[i] % 10);
	serial1[sizeof(serial1) - 1] = '\0';
	GTLS_CHECK(gnutls_rnd(GNUTLS_RND_KEY, serial2, sizeof(serial2)));
	for(unsigned int i = 0; i < sizeof(serial2) - 1; i++)
		serial2[i] = '0' + (serial2[i] % 10);
	serial2[sizeof(serial2) - 1] = '\0';

	// Create validity period
	// Use YYYYMMDDHHMMSS as required by RFC 5280 (UTCTime)
	time_t not_before;
	time_t not_after;
	{
		const time_t now = time(NULL);
		struct tm tms = { 0 };
		struct tm *tm = localtime_r(&now, &tms);
		not_before = now;
		tm->tm_year += 30; // 30 years from now
		// Check for leap year, and adjust the date accordingly
		const bool isLeapYear = tm->tm_year % 4 == 0 && (tm->tm_year % 100 != 0 || tm->tm_year % 400 == 0);
		tm->tm_mday = tm->tm_mon == 1 && tm->tm_mday == 29 && !isLeapYear ? 28 : tm->tm_mday;
		not_after = mktime(tm);
		if(not_after == (time_t)-1)
			goto clean;
	}

	// 1. Create CA certificate
	const char *err = NULL;
	unsigned char ca_key_id[SHA1_DIGEST_SIZE] = { 0, };
	size_t ca_key_id_size = sizeof(ca_key_id);

	printf("Generating new CA with serial number %s...\n", serial1);

	GTLS_CHECK(gnutls_x509_crt_set_version(ca_crt, 3));
	GTLS_CHECK(gnutls_x509_crt_set_pubkey(ca_crt, ca_pubkey));
	GTLS_CHECK(gnutls_x509_crt_get_key_id(ca_crt, GNUTLS_KEYID_USE_SHA1, ca_key_id, &ca_key_id_size));
	GTLS_CHECK(gnutls_x509_crt_set_subject_key_id(ca_crt, ca_key_id, ca_key_id_size));
	GTLS_CHECK(gnutls_x509_crt_set_activation_time(ca_crt, not_before));
	GTLS_CHECK(gnutls_x509_crt_set_basic_constraints(ca_crt, 1, -1));
	GTLS_CHECK(gnutls_x509_crt_set_dn(ca_crt, "CN=pi.hole,O=Pi-hole,C=DE", &err));
	GTLS_CHECK(gnutls_x509_crt_set_expiration_time(ca_crt, not_after));
	GTLS_CHECK(gnutls_x509_crt_set_issuer_dn(ca_crt, "CN=pi.hole,O=Pi-hole,C=DE", &err));
	GTLS_CHECK(gnutls_x509_crt_set_key_usage(ca_crt, GNUTLS_KEY_KEY_CERT_SIGN));
	GTLS_CHECK(gnutls_x509_crt_set_serial(ca_crt, serial1, sizeof(serial1)-1));
	// This step must be the last generation step
	GTLS_CHECK(gnutls_x509_crt_sign2(ca_crt, ca_crt, ca_privkey, GNUTLS_DIG_SHA256, 0));
	// Export certificate in PEM format
	GTLS_CHECK(gnutls_x509_crt_export2(ca_crt, GNUTLS_X509_FMT_PEM, &ca_crt_buffer));

	// Documented GnuTLS "feature": Need to re-import the certificate to become usable...
	gnutls_x509_crt_deinit(ca_crt);
	if((rc = gnutls_x509_crt_init(&ca_crt)) != GNUTLS_E_SUCCESS)
	{
		ca_crt = NULL;
		goto clean;
	}
	GTLS_CHECK(gnutls_x509_crt_import(ca_crt, &ca_crt_buffer, GNUTLS_X509_FMT_PEM));

	printf("Generating new server certificate with serial number %s...\n", serial2);

	unsigned char key_id[SHA1_DIGEST_SIZE] = { 0, };
	size_t key_id_size = sizeof(ca_key_id);
	GTLS_CHECK(gnutls_x509_crt_set_version(srv_crt, 3));
	GTLS_CHECK(gnutls_x509_crt_set_pubkey(srv_crt, srv_pubkey));
	GTLS_CHECK(gnutls_x509_crt_get_key_id(srv_crt, GNUTLS_KEYID_USE_SHA1, key_id, &key_id_size));
	GTLS_CHECK(gnutls_x509_crt_set_subject_key_id(srv_crt, key_id, key_id_size));
	GTLS_CHECK(gnutls_x509_crt_set_authority_key_id(srv_crt, ca_key_id, ca_key_id_size));
	GTLS_CHECK(gnutls_x509_crt_set_activation_time(srv_crt, not_before));
	GTLS_CHECK(gnutls_x509_crt_set_basic_constraints(srv_crt, 0, -1));
	GTLS_CHECK(gnutls_x509_crt_set_expiration_time(srv_crt, not_after));
	GTLS_CHECK(gnutls_x509_crt_set_issuer_dn(srv_crt, "CN=pi.hole,O=Pi-hole,C=DE", &err));
	GTLS_CHECK(gnutls_x509_crt_set_key_purpose_oid(srv_crt, GNUTLS_KP_TLS_WWW_SERVER, 0));
	GTLS_CHECK(gnutls_x509_crt_set_serial(srv_crt, serial2, sizeof(serial2)-1));

	// Set subject name depending on the (optionally) specified domain
	//
	// Since RFC 2818 (May 2000), the Common Name (CN) field is ignored
	// in certificates if the subject alternative name extension is present.
	//
	// Furthermore, RFC 3280 (4.2.1.7, 1. paragraph) specifies that
	// subjectAltName must always be used and that the use of the CN field
	// should be limited to support legacy implementations.
	//
	// Add the domain and all sub-domains as DNS subject alternative name (SAN)
	// when a custom domain is used to make the certificate more universal
	if((subject_name = calloc(strlen(domain) + 6, sizeof(char))) == NULL)
		goto clean;

	strcpy(subject_name, "CN=");
	if(strcasecmp(domain, "pi.hole") == 0)
	{
		strcpy(subject_name + 3, domain);
	}
	else
	{
		char *dn = subject_name + 3;
		const char *dnp_san, *dnw_san;

		if(strcmp(domain, "*.") == 0)
		{
			dnp_san = domain + 2;
			dnw_san = domain;
		}
		else
		{
			strcpy(dn, "*.");
			dnp_san = domain;
			dnw_san = dn;
			dn += 2;
		}
		strcpy(dn, domain);

		GTLS_CHECK(gnutls_x509_crt_set_subject_alt_name(srv_crt,
	                                                    GNUTLS_SAN_DNSNAME,
	                                                    dnw_san,
	                                                    strlen(dnw_san),
	                                                    GNUTLS_FSAN_SET));
		GTLS_CHECK(gnutls_x509_crt_set_subject_alt_name(srv_crt,
	                                                    GNUTLS_SAN_DNSNAME,
	                                                    dnp_san,
	                                                    strlen(dnp_san),
	                                                    GNUTLS_FSAN_APPEND));
	}
	GTLS_CHECK(gnutls_x509_crt_set_dn(srv_crt, subject_name, &err));
	// Add "DNS:pi.hole" as DNS subject alternative name (SAN)
	GTLS_CHECK(gnutls_x509_crt_set_subject_alt_name(srv_crt, GNUTLS_SAN_DNSNAME, "pi.hole", 7, GNUTLS_FSAN_APPEND));
	// This step must be the last generation step
	GTLS_CHECK(gnutls_x509_crt_sign2(srv_crt, ca_crt, ca_privkey, GNUTLS_DIG_SHA256, 0));
	// Export certificate in PEM format
	GTLS_CHECK(gnutls_x509_crt_export2(srv_crt, GNUTLS_X509_FMT_PEM, &srv_crt_buffer));

	// Create file with CA certificate only
	write_to_file(certfile, "CA certificate", "_ca.crt", (char*)ca_crt_buffer.data, NULL);

	// Create file with server certificate only
	write_to_file(certfile, "server certificate", ".crt", (char*)srv_crt_buffer.data, NULL);

	// Write server's private key and certificate to file
	write_to_file(certfile, "server key + certificate", NULL, (char*)srv_crt_buffer.data, (char*)srv_key_buffer.data);

	res = true;

clean:
	// Free resources
	gnutls_x509_crt_deinit(ca_crt);
	gnutls_x509_crt_deinit(srv_crt);
	gnutls_x509_privkey_deinit(ca_privkey);
	gnutls_x509_privkey_deinit(srv_privkey);
	gnutls_pubkey_deinit(ca_pubkey);
	gnutls_pubkey_deinit(srv_pubkey);
	gnutls_free(ca_crt_buffer.data);
	gnutls_free(ca_key_buffer.data);
	gnutls_free(srv_crt_buffer.data);
	gnutls_free(srv_key_buffer.data);
	gnutls_free(subject_name);

	return res;
}

static bool check_wildcard_domain(const char *domain, const char *san, const size_t san_len)
{
	// Also check if the SAN is a wildcard domain and if the domain
	// matches the wildcard (e.g. "*.pi-hole.net" and "abc.pi-hole.net")
	const bool is_wild = san_len > 1 && san[0] == '*';
	if(!is_wild)
		return false;

	// The domain must be at least as long as the wildcard domain
	const size_t domain_len = strlen(domain);
	if(domain_len < san_len - 1)
		return false;

	// Check if the domain ends with the wildcard domain
	// Attention: The SAN is not NUL-terminated, so we need to
	//            use the length field
	const char *wild_domain = domain + domain_len - san_len + 1;
	return strncasecmp(wild_domain, san + 1, san_len) == 0;
}

static int gtls_x509_parse_certfile(gnutls_x509_crt_t *crt, const char *certfile)
{
	gnutls_datum_t data = { NULL, 0 };

	int rc;
	GTLS_CHECK(gnutls_load_file(certfile, &data));
	GTLS_CHECK(gnutls_x509_crt_init(crt));
	if((rc = gnutls_x509_crt_import(*crt, &data, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS)
	{
		gnutls_x509_crt_deinit(*crt);
		*crt = NULL;
	}

clean:
	gnutls_free(data.data);

	return rc;
}

static int gtls_x509_parse_keyfile(gnutls_x509_privkey_t *key, const char *keyfile)
{
	gnutls_datum_t data = { NULL, 0 };

	int rc;
	GTLS_CHECK(gnutls_load_file(keyfile, &data));
	GTLS_CHECK(gnutls_x509_privkey_init(key));
	if((rc = gnutls_x509_privkey_import2(*key, &data, GNUTLS_X509_FMT_PEM, NULL,
											GNUTLS_PKCS_PLAIN | GNUTLS_PKCS_NULL_PASSWORD)) != GNUTLS_E_SUCCESS)
	{
		gnutls_x509_privkey_deinit(*key);
		*key = NULL;
	}

clean:
	if(data.data != NULL)
	{
		gnutls_memset(data.data, 0, data.size);
		gnutls_free(data.data);
	}

	return rc;
}

static void printf_hex(const unsigned char *data, size_t size, const char *separator, bool skip_leading_zero)
{
	if (data == NULL || size == 0)
		return;

	const char* sep[2] =  { "", (separator == NULL) ? "" : separator };
	int s = 0;

	if (skip_leading_zero && data[0] == 0 && size > 1)
	{
		data++;
		size--;
	}

	for(size_t i = 0; i < size; i++)
	{
		printf("%s%02X", sep[s], data[i]);
		s = 1;
	}
}

static void gtls_x509_crt_info(gnutls_x509_crt_t crt, const char *indent)
{
	int rc;

	if(indent == NULL)
		indent = "";

	// Version
	{
		printf("%scert. version     : ", indent);
		if((rc = gnutls_x509_crt_get_version(crt)) >= 0)
			printf("%d", rc);
		puts("");
	}

	// Serial
	{
		unsigned char buf[BUFFER_SIZE];
		size_t size = BUFFER_SIZE;

		printf("%sserial number     : ", indent);
		if((rc = gnutls_x509_crt_get_serial(crt, buf, &size)) == GNUTLS_E_SUCCESS)
			printf_hex(buf, size, ":", false);
		puts("");
	}

	// Issuer
	{
		gnutls_datum_t data = { NULL, 0 };

		printf("%sissuer name       : ", indent);
		rc = gnutls_x509_crt_get_issuer_dn3(crt, &data, 0);
		puts((rc == GNUTLS_E_SUCCESS) ? (const char *)data.data : "");
		gnutls_free(data.data);
	}

	// Subject
	{
		gnutls_datum_t data = { NULL, 0 };

		printf("%ssubject name      : ", indent);
		rc = gnutls_x509_crt_get_dn3(crt, &data, 0);
		puts((rc == GNUTLS_E_SUCCESS) ? (const char *)data.data : "");
		gnutls_free(data.data);
	}

	// Valid from
	{
		time_t time;

		printf("%sissued  on        : ", indent);
		if((time = gnutls_x509_crt_get_activation_time(crt)) != (time_t)-1)
		{
			struct tm utc;

			if(gmtime_r(&time, &utc) != NULL)
				printf("%04d-%02d-%02d %02d:%02d:%02d UTC",
				       utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
					   utc.tm_hour, utc.tm_min, utc.tm_sec);
		}
		puts("");
	}

	// Valid to
	{
		time_t time;

		printf("%sexpires on        : ", indent);
		if((time = gnutls_x509_crt_get_expiration_time(crt)) != (time_t)-1)
		{
			struct tm utc;

			if(gmtime_r(&time, &utc) != NULL)
				printf("%04d-%02d-%02d %02d:%02d:%02d UTC",
				       utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
					   utc.tm_hour, utc.tm_min, utc.tm_sec);
		}
		puts("");
	}

	// Signature algorithm
	{
		printf("%ssigned using      : ", indent);
		rc = gnutls_x509_crt_get_signature_algorithm(crt);
#if GNUTLS_VERSION_NUMBER < 0x030600
		puts((rc > 0) ? gnutls_sign_get_name(rc) : "");
#else
		puts((rc != GNUTLS_SIGN_UNKNOWN)? gnutls_sign_get_name(rc) : "");
#endif
	}

	// Private key algorithm and size
	{
		unsigned int bits = 0;

		if((rc = gnutls_x509_crt_get_pk_algorithm(crt, &bits)) != GNUTLS_PK_UNKNOWN)
		{
			const char *name = gnutls_pk_get_name(rc);
			int len = (int)strlen(name);

			printf("%s%s key size%*s: %u bits\n",
			       indent, name, (len > 9) ? 1 : 9 - len, "", bits);
		}
	}

	// Basic constraints
	{
		unsigned int ca;
		int len = 0;

		if((rc = gnutls_x509_crt_get_basic_constraints(crt, NULL, &ca, &len)) >= 0)
		{
			printf("%sbasic constraints : CA=%s", indent, ca ? "true" : "false");
			if(len > 0)
				printf(", max_pathlen=%d", len);
			puts("");
		}
	}

	// Subject alternative names
	{
		gnutls_datum_t data = { NULL, 0 };

		// Loop over all SANs
		for(int seq = 0;; seq++)
		{
			size_t size = data.size;
			unsigned int type = 0;

			rc = gnutls_x509_crt_get_subject_alt_name2(crt, seq, data.data, &size, &type, NULL);
			// No more SANs
			if(rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;

			// Buffer is too small
			if(rc == GNUTLS_E_SHORT_MEMORY_BUFFER)
			{
				// Resize buffer
				data.data = gnutls_realloc(data.data, size);
				data.size = size;
				seq--;

				if(data.data == NULL)
					break;

				continue;
			}

			if(seq == 0)
				printf("%ssubject alt name  :\n", indent);

			switch(type)
			{
			// otherName - TODO

			// dNSName
			case GNUTLS_SAN_DNSNAME:    /* fall through */
				printf("%s    dNSName : %*s\n", indent, (int)size, data.data);
				break;

			// RFC822 Name
			case GNUTLS_SAN_RFC822NAME: /* fall through */
				printf("%s    rfx822Name : %*s\n", indent, (int)size, data.data);
				break;

			// uniformResourceIdentifier
			case GNUTLS_SAN_URI:
				printf("%s    uniformResourceIdentifier : %*s\n", indent, (int)size, data.data);
				break;

			// iPAddress
			case GNUTLS_SAN_IPADDRESS:
			{
				printf("%s    iPAddress : ", indent);
				unsigned char *ip = data.data;

				// Only IPv6 (16 bytes) and IPv4 (4 bytes) types are supported
				switch(size)
				{
				case 4:
					printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
					break;
				case 16:
					printf("%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X:%X%X\n",
					       ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
					       ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
					break;
				default:
					puts("");
					break;
				}

				break;
			}

			// directoryName - TODO

			// Unknown/unsupported
			default:
				printf("%s    <unsupported>\n", indent);
				break;
			}
		}

		// Free resources
		gnutls_free(data.data);
	}

}

// This function reads a X.509 certificate from a file and prints a
// human-readable representation of the certificate to stdout. If a domain is
// specified, we only check if this domain is present in the certificate.
// Otherwise, we print verbose human-readable information about the certificate
// and about the private key (if requested).
enum cert_check read_certificate(const char* certfile, const char *domain, const bool private_key)
{
	if(certfile == NULL && domain == NULL)
	{
		log_err("No certificate file specified\n");
		return CERT_FILE_NOT_FOUND;
	}

	enum cert_check res = CERT_CANNOT_PARSE_CERT;
	gnutls_x509_crt_t crt = NULL;
	gnutls_x509_privkey_t privkey = NULL;
	gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t data = { NULL, 0 };
	size_t size;

	log_info("Reading certificate from %s ...", certfile);

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	bool has_key;
	int rc;
	if((rc = gtls_x509_parse_certfile(&crt, certfile)) != GNUTLS_E_SUCCESS)
	{
		log_err("Cannot parse certificate (%d): %s", rc, gnutls_strerror(rc));
		return CERT_CANNOT_PARSE_CERT;
	}

	if((rc = gtls_x509_parse_keyfile(&privkey, certfile)) == GNUTLS_E_SUCCESS)
	{
		gnutls_certificate_credentials_t crd = NULL;

		if((rc = gnutls_certificate_allocate_credentials(&crd)) == GNUTLS_E_SUCCESS)
			rc = gnutls_certificate_set_x509_key(crd, &crt, 1, privkey);

		gnutls_certificate_free_credentials(crd);

		if(rc < 0)
		{
			log_err("Certificate and key don't match");
			res = CERT_KEY_MISMATCH;
			goto clean;
		}

		has_key = true;
	}
	else
	{
		log_info("No key found");
		has_key = false;
	}

	// Check for domain
	if(domain != NULL)
	{
		bool found = false;

		// Loop over all SANs
		for(int seq = 0;; seq++)
		{
			size = data.size;
			unsigned int type = 0;

			rc = gnutls_x509_crt_get_subject_alt_name2(crt, seq, data.data, &size, &type, NULL);
			// No more SANs
			if(rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;

			// Check if SAN is a DNS name, skip otherwise
			if (type != GNUTLS_SAN_DNSNAME)
				continue;

			// Buffer is too small
			if(rc == GNUTLS_E_SHORT_MEMORY_BUFFER)
			{
				// Resize buffer
				data.data = gnutls_realloc(data.data, size);
				data.size = size;
				seq--;

				if(data.data == NULL)
				{
					res = CERT_CANNOT_PARSE_CERT;
					goto clean;
				}

				continue;
			}

			// Check if the SAN matches the domain
			if(strncasecmp(domain, (const char*)data.data, size) == 0)
			{
				found = true;
				break;
			}

			// Also check if the SAN is a wildcard domain and if the domain
			// matches the wildcard
			if(check_wildcard_domain(domain, (const char*)data.data, size))
			{
				found = true;
				break;
			}
		}

		// Also check against the common name (CN) field
		if(!found)
		{
			// Free resources
			gnutls_free(data.data);

			if((rc = gnutls_x509_crt_get_dn3(crt, &data, 0)) != GNUTLS_E_SUCCESS)
			{
				res = CERT_CANNOT_PARSE_CERT;
				goto clean;
			}

			// Ouput format see RFC 4514
			if(data.size > 3 && strncasecmp((const char *)data.data, "CN=", 3) == 0)
			{
				const char *cn = ((const char*)data.data) + 3;
				if(strcasecmp(domain, cn) == 0)
					found = true;
				else if (check_wildcard_domain(domain, cn, strlen(cn)))
					found = true;
			}
		}

		// Free resources
		gnutls_free(data.data);

		return found ? CERT_DOMAIN_MATCH : CERT_DOMAIN_MISMATCH;
	}

	// else: Print verbose information about the certificate
	char certinfo[BUFFER_SIZE] = { 0 };
	puts("Certificate (X.509):\n");
	gtls_x509_crt_info(crt, "  ");
	puts("");

	if(!private_key || !has_key)
		goto end;

	unsigned int bits = 0;
	puts("Private key:");
	if((rc = gnutls_x509_crt_get_pk_algorithm(crt, &bits)) != GNUTLS_PK_UNKNOWN)
		printf("  Type: %s\n", gnutls_pk_get_name(rc));

	if(rc == GNUTLS_PK_ECDSA)
	{
		gnutls_ecc_curve_t curve;
		gnutls_datum_t k = { NULL, 0 };
		gnutls_datum_t x = { NULL, 0 };
		gnutls_datum_t y = { NULL, 0 };

		if((rc = gnutls_x509_privkey_export_ecc_raw(privkey, &curve, &x, &y, &k)) == GNUTLS_E_SUCCESS)
		{
			unsigned int bitlen = 0;

			for(size_t i = 0; i < k.size; i++)
				if(k.data[i] != 0)
				{
					unsigned char b = k.data[i];

					bitlen = (k.size - i - 1) * 8;
					do
					{
						bitlen++;
					} while (b >>= 1);

					break;
				}

			printf("  Bitlen: %u bit\n", bitlen);

			switch(curve)
			{
			case GNUTLS_ECC_CURVE_ED25519:     /* fall through */
			case GNUTLS_ECC_CURVE_ED448:       /* fall through */
			case GNUTLS_ECC_CURVE_X25519:      /* fall through */
			case GNUTLS_ECC_CURVE_X448:
				puts("  Curve type: Montgomery (y^2 = x^3 + a x^2 + x)");
				break;

			case GNUTLS_ECC_CURVE_SECP192R1:   /* fall through */
			case GNUTLS_ECC_CURVE_SECP224R1:   /* fall through */
			case GNUTLS_ECC_CURVE_SECP256R1:   /* fall through */
			case GNUTLS_ECC_CURVE_SECP384R1:   /* fall through */
			case GNUTLS_ECC_CURVE_SECP521R1:
				puts("  Curve type: Short Weierstrass (y^2 = x^3 + a x + b)");
				break;

			case GNUTLS_ECC_CURVE_GOST256A:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST256B:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST256C:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST256CPA:  /* fall through */
			case GNUTLS_ECC_CURVE_GOST256CPB:  /* fall through */
			case GNUTLS_ECC_CURVE_GOST256CPC:  /* fall through */
			case GNUTLS_ECC_CURVE_GOST256CPXA: /* fall through */
			case GNUTLS_ECC_CURVE_GOST256CPXB: /* fall through */
			case GNUTLS_ECC_CURVE_GOST256D:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST512A:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST512B:    /* fall through */
			case GNUTLS_ECC_CURVE_GOST512C:    /* fall through */
				// TODO GOST support
			case GNUTLS_ECC_CURVE_INVALID:
				puts("  Curve type: Unknown");
				break;
			}

			fputs("  Private key:\n    D = 0x", stdout);
			printf_hex(k.data, k.size, NULL, true);

			fputs("\n  Public key:\n    X = 0x", stdout);
			printf_hex(x.data, x.size, NULL, true);

			fputs("\n    Y = 0x", stdout);
			printf_hex(y.data, y.size, NULL, true);
			puts("\n    Z = 0x01\n");
		}

		gnutls_free(k.data);
		gnutls_free(x.data);
		gnutls_free(y.data);
	}
	else if(rc == GNUTLS_PK_RSA)
	{
		gnutls_datum_t ce = { NULL, 0 };
		gnutls_datum_t d = { NULL, 0 };
		gnutls_datum_t e = { NULL, 0 };
		gnutls_datum_t e1 = { NULL, 0 };
		gnutls_datum_t e2 = { NULL, 0 };
		gnutls_datum_t m = { NULL, 0 };
		gnutls_datum_t p = { NULL, 0 };
		gnutls_datum_t q = { NULL, 0 };

		if((rc = gnutls_x509_privkey_export_rsa_raw2(privkey, &m, &e, &d, &p, &q, &ce, &e1, &e2)) == GNUTLS_E_SUCCESS)
		{
			printf("  RSA modulus: %u bit\n  Core parameters:\n    Exponent:\n      E = 0x", bits);
			printf_hex(e.data, e.size, NULL, true);
			fputs("\n    Modulus:\n      N = 0x", stdout);
			printf_hex(m.data, m.size, NULL, true);
			fputs("\n    Prime factors:\n      P = 0x", stdout);
			printf_hex(p.data, p.size, NULL, true);
			fputs("\n      Q = 0x", stdout);
			printf_hex(q.data, q.size, NULL, true);
			fputs("\n    Private exponent:\n      D = 0x", stdout);
			printf_hex(d.data, d.size, NULL, true);
			fputs("\n  CRT parameters:\n    D mod (P-1):\n      DP = 0x", stdout);
			printf_hex(e1.data, e1.size, NULL, true);
			fputs("\n    D mod (Q-1):\n      DQ = 0x", stdout);
			printf_hex(e2.data, e2.size, NULL, true);
			fputs("\n    Q^-1 mod P:\n      QP = 0x", stdout);
			printf_hex(ce.data, ce.size, NULL, true);
			puts("\n");
		}

		gnutls_free(ce.data);
		gnutls_free(d.data);
		gnutls_free(e.data);
		gnutls_free(e1.data);
		gnutls_free(e2.data);
		gnutls_free(m.data);
		gnutls_free(p.data);
		gnutls_free(q.data);
	}
	else
	{
		puts("Sorry, but FTL does not know how to print key information for this type\n");
		goto end;
	}

	// Print private key in PEM format
	size = BUFFER_SIZE;
	GTLS_CHECK_GOTO(gnutls_x509_privkey_export(privkey, GNUTLS_X509_FMT_PEM, certinfo, &size), end);

	puts("Private key (PEM):");
	puts(certinfo);

end:
	// Say ok even if we can't finally print the PEM
	res = CERT_OKAY;

	// Print public key in PEM format
	size = BUFFER_SIZE;
	GTLS_CHECK(gnutls_pubkey_init(&pubkey));
	GTLS_CHECK(gnutls_pubkey_import_x509(pubkey, crt, 0));
	GTLS_CHECK(gnutls_pubkey_export(pubkey, GNUTLS_X509_FMT_PEM, certinfo, &size));

	puts("Public key (PEM):");
	puts(certinfo);

clean:
	// Free resources
	gnutls_pubkey_deinit(pubkey);
	gnutls_x509_crt_deinit(crt);
	gnutls_x509_privkey_deinit(privkey);

	return res;
}

#else

bool generate_certificate(const char* certfile, bool rsa, const char *domain)
{
	log_err("FTL was not compiled with GnuTLS support");
	return false;
}

enum cert_check read_certificate(const char* certfile, const char *domain, const bool private_key)
{
	log_err("FTL was not compiled with GnuTLS support");
	return CERT_FILE_NOT_FOUND;
}

#endif
