/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "toml_reader.h"
#include "log.h"
// getprio(), setprio()
#include <sys/resource.h>
// argv_dnsmasq
#include "args.h"
// INT_MAX
#include <limits.h>
#include "datastructure.h"
// openFTLtoml()
#include "config/toml_helper.h"
// delete_all_sessions()
#include "api/api.h"
// readEnvValue()
#include "config/env.h"

// Private prototypes
static toml_table_t *parseTOML(void);
static void reportDebugFlags(void);

bool readFTLtoml(struct config *oldconf, struct config *newconf,
                 toml_table_t *toml, const bool verbose, bool *restart)
{
	// Parse lines in the config file if we did not receive a pointer to a TOML
	// table from an imported Teleporter file
	bool teleporter = (toml != NULL);
	if(!teleporter)
	{
		toml = parseTOML();
		if(!toml)
			return false;
	}

	// First, get an array of keys of config items that have been forced
	// through environment variables
	cJSON *env_vars = read_forced_vars();

	// Try to read debug config. This is done before the full config
	// parsing to allow for debug output further down
	// First try to read env variable, if this fails, read TOML
	if(teleporter || !readEnvValue(&newconf->debug.config, newconf, env_vars, NULL))
	{
		toml_table_t *conf_debug = toml_table_in(toml, "debug");
		if(conf_debug)
			readTOMLvalue(&newconf->debug.config, "config", conf_debug, newconf);
	}
	set_debug_flags(newconf);

	log_debug(DEBUG_CONFIG, "Reading %s TOML config file",
	          teleporter ? "teleporter" : "default");

	// Read all known config items
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		// Get pointer to memory location of this conf_item
		// oldconf can be NULL when reading a Teleporter file
		struct conf_item *old_conf_item = oldconf != NULL ? get_conf_item(oldconf, i) : NULL;
		struct conf_item *new_conf_item = get_conf_item(newconf, i);

		// First try to read this config option from an environment variable
		// Skip reading environment variables when importing from Teleporter
		// If this succeeds, skip searching the TOML file for this config item
		bool reset = false;
		if(!teleporter && readEnvValue(new_conf_item, newconf, env_vars, &reset))
		{
			new_conf_item->f |= FLAG_ENV_VAR;
			continue;
		}

		// Skip this variable if it has been reset (forced by
		// environment variable before but not anymore)
		if(reset)
		{
			if(new_conf_item->t == CONF_ALL_DEBUG_BOOL)
			{
				// Reset all debug flags to false if debug.all
				// has been reset
				set_all_debug(newconf, false);
				set_debug_flags(newconf);
			}
			log_info("Skipping %s as it has been reset", new_conf_item->k);
			continue;
		}

		// Get config path depth
		unsigned int level = config_path_depth(new_conf_item->p);

		// Parse tree of properties
		bool item_available = true;
		toml_table_t *table[MAX_CONFIG_PATH_DEPTH] = { 0 };
		for(unsigned int j = 0; j < level-1; j++)
		{
			// Get table at this level
			table[j] = toml_table_in(j > 0 ? table[j-1] : toml, new_conf_item->p[j]);
			if(!table[j])
			{
				log_debug(DEBUG_CONFIG, "%s DOES NOT EXIST", new_conf_item->k);
				item_available = false;
				break;
			}
		}

		// Skip this config item if it does not exist
		if(!item_available)
			continue;

		// Try to parse config item
		readTOMLvalue(new_conf_item, new_conf_item->p[level-1], table[level-2], newconf);

		// Check if we need to restart FTL
		if(old_conf_item != NULL &&
		   !compare_config_item(new_conf_item->t, &old_conf_item->v, &new_conf_item->v))
		{
			log_debug(DEBUG_CONFIG, "%s CHANGED", new_conf_item->k);
			if(new_conf_item->f & FLAG_RESTART_FTL && restart != NULL)
				*restart = true;

			// Check if this item changed the password, if so, we need to
			// invalidate all currently active sessions
			if(new_conf_item->f & FLAG_INVALIDATE_SESSIONS)
				delete_all_sessions();
		}
	}

	// Report debug config if enabled
	set_debug_flags(newconf);
	if(verbose)
		reportDebugFlags();

	// Print FTL environment variables (if used)
	printFTLenv();

	// Free memory allocated by the TOML parser and return success
	toml_free(toml);
	cJSON_Delete(env_vars);
	return true;
}

// Parse TOML config file
static toml_table_t *parseTOML(void)
{
	// Try to open default config file. Use fallback if not found
	bool locked = false;
	FILE *fp = openFTLtoml("r", &locked);
	if(fp == NULL)
		return NULL;

	// Parse lines in the config file
	char errbuf[200];
	toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));

	// Close file and release exclusive lock
	closeFTLtoml(fp, locked);

	// Check for errors
	if(conf == NULL)
	{
		log_err("Cannot parse config file: %s", errbuf);
		return NULL;
	}

	log_debug(DEBUG_CONFIG, "TOML file parsing: OK");
	return conf;
}

bool getLogFilePathTOML(void)
{
	log_debug(DEBUG_CONFIG, "Reading TOML config file: log file path");

	toml_table_t *conf = parseTOML();
	if(!conf)
		return false;

	toml_table_t *files = toml_table_in(conf, "files");
	if(!files)
	{
		log_debug(DEBUG_CONFIG, "files does not exist");
		toml_free(conf);
		return false;
	}

	toml_datum_t log = toml_string_in(files, "log");
	if(!log.ok)
	{
		log_debug(DEBUG_CONFIG, "files.log DOES NOT EXIST");
		toml_free(conf);
		return false;
	}

	// Only replace string when it is different
	if(strcmp(config.files.log.ftl.v.s,log.u.s) != 0)
	{
		config.files.log.ftl.t = CONF_STRING_ALLOCATED;
		config.files.log.ftl.v.s = log.u.s; // Allocated string
	}
	else
		free(log.u.s);

	toml_free(conf);
	return true;
}

static void reportDebugFlags(void)
{
	// Print debug settings
	log_debug(DEBUG_ANY, "************************");
	log_debug(DEBUG_ANY, "*    DEBUG SETTINGS    *");

	// Read all known debug config items
	for(unsigned int debug_flag = 1; debug_flag < DEBUG_ELEMENTS; debug_flag++)
	{
		// Get name of debug flag
		// We do not need to add an offset as this loop starts counting
		// at 1
		const char *name = debugstr(debug_flag);
		// Calculate number of spaces to nicely align output
		int spaces = 20 - strlen(name);
		// Print debug flag
		// We skip the first 6 characters of the flags as they are always "DEBUG_"
		log_debug(DEBUG_ANY, "* %s:%*s %s  *", name+6, spaces, "", debug_flags[debug_flag] ? "YES" : "NO ");
	}
	log_debug(DEBUG_ANY, "************************");
}
