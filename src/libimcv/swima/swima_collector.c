/*
 * Copyright (C) 2017 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "swima_collector.h"

#include <collections/linked_list.h>
#include <bio/bio_writer.h>
#include <utils/debug.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>

#define SOURCE_ID_GENERATOR		1
#define SOURCE_ID_COLLECTOR		2

#define SWID_GENERATOR	"/usr/local/bin/swid_generator"
#define SWID_DIRECTORY	"/usr/share"

/**
 * Directories to be skipped by collector
 */
static const char* skip_directories[] = {
	"/usr/share/doc",
	"/usr/share/help",
	"/usr/share/icons",
	"/usr/share/gnome/help"
};

typedef struct private_swima_collector_t private_swima_collector_t;

/**
 * Private data of a swima_collector_t object.
 *
 */
struct private_swima_collector_t {

	/**
	 * Public swima_collector_t interface.
	 */
	swima_collector_t public;

	/**
	 * Collect Software Identifiers only
	 */
	bool sw_id_only;

	/**
	 * List of SWID tags or tag IDs
	 */
	swima_inventory_t *inventory;

};

/**
 * Extract Software Identifier from SWID tag
 */
static status_t extract_sw_id(chunk_t swid_tag, chunk_t *sw_id)
{
	char *pos, *tag, *tagid, *regid;
	size_t len, tagid_len, regid_len;
	status_t status = NOT_FOUND;

	/* Copy at most 1023 bytes of the SWID tag and null-terminate it */
	len = min(1023, swid_tag.len);
	pos = tag = strndup(swid_tag.ptr, len);

	tagid= strstr(pos, "tagId=\"");
	if (tagid == NULL)
	{
		goto end;
	}
	tagid += 7;
	len -= tagid - pos - 7;

	pos = strchr(tagid, '"');
	if (pos == NULL)
	{
		goto end;
	}
	tagid_len = pos - tagid;

	regid= strstr(pos, "regid=\"");
	if (regid == NULL)
	{
		goto end;
	}
	regid += 7;
	len -= regid - pos - 7;

	pos = strchr(regid, '"');
	if (pos == NULL)
	{
		goto end;
	}
	regid_len = pos - regid;

	*sw_id = chunk_cat("ccc", chunk_create(regid, regid_len),
							  chunk_from_chars('_'),
							  chunk_create(tagid, tagid_len));
	status = SUCCESS;
end:
	free(tag);

	return status;
}

/**
 * Read SWID tags issued by the swid_generator tool
 */
static status_t read_swid_tags(private_swima_collector_t *this, FILE *file)
{
	swima_record_t *sw_record;
	bio_writer_t *writer;
	chunk_t sw_id, swid_tag;
	bool more_tags = TRUE, last_newline;
	char line[8192];
	size_t len;
	status_t status;

	while (more_tags)
	{
		last_newline = TRUE;
		writer = bio_writer_create(512);
		while (TRUE)
		{
			if (!fgets(line, sizeof(line), file))
			{
				more_tags = FALSE;
				break;
			}
			len = strlen(line);

			if (last_newline && line[0] == '\n')
			{
				break;
			}
			else
			{
				last_newline = (line[len-1] == '\n');
				writer->write_data(writer, chunk_create(line, len));
			}
		}
		swid_tag = writer->get_buf(writer);

		if (swid_tag.len > 1)
		{
			/* remove trailing newline if present */
			if (swid_tag.ptr[swid_tag.len - 1] == '\n')
			{
				swid_tag.len--;
			}
			DBG3(DBG_IMC, "  %.*s", swid_tag.len, swid_tag.ptr);

			status = extract_sw_id(swid_tag, &sw_id);
			if (status != SUCCESS)
			{
				DBG1(DBG_IMC, "software id could not be extracted from tag");
				writer->destroy(writer);
				return status;
			}
			sw_record = swima_record_create(0, sw_id, chunk_empty);
			sw_record->set_source_id(sw_record, SOURCE_ID_GENERATOR);
			sw_record->set_record(sw_record, swid_tag);
			this->inventory->add(this->inventory, sw_record);
			chunk_free(&sw_id);
		}
		writer->destroy(writer);
	}

	return SUCCESS;
}

/**
 * Read Software Identifiers issued by the swid_generator tool
 */
static status_t read_swid_tag_ids(private_swima_collector_t *this, FILE *file)
{
	swima_record_t *sw_record;
	chunk_t sw_id;
	char line[BUF_LEN];
	size_t len;

	while (TRUE)
	{
		if (!fgets(line, sizeof(line), file))
		{
			return SUCCESS;
		}
		len = strlen(line);

		/* remove trailing newline if present */
		if (len > 0 && line[len - 1] == '\n')
		{
			len--;
		}
		DBG3(DBG_IMC, "  %.*s", len, line);

		sw_id = chunk_create(line, len);
		sw_record = swima_record_create(0, sw_id, chunk_empty);
		sw_record->set_source_id(sw_record, SOURCE_ID_GENERATOR);
		this->inventory->add(this->inventory, sw_record);
	}
}

static status_t generate_tags(private_swima_collector_t *this, char *generator,
							swima_inventory_t *targets, bool pretty, bool full)
{
	FILE *file;
	char command[BUF_LEN];
	char doc_separator[] = "'\n\n'";

	status_t status = SUCCESS;

	if (targets->get_count(targets) == 0)
	{
		/* Assemble the SWID generator command */
		if (this->sw_id_only)
		{
			snprintf(command, BUF_LEN, "%s software-id", generator);
		}
		else
		{
			snprintf(command, BUF_LEN, "%s swid --doc-separator %s%s%s",
					 generator, doc_separator, pretty ? " --pretty" : "",
											   full   ? " --full"   : "");
		}

		/* Open a pipe stream for reading the SWID generator output */
		file = popen(command, "r");
		if (!file)
		{
			DBG1(DBG_IMC, "failed to run swid_generator command");
			return NOT_SUPPORTED;
		}

		if (this->sw_id_only)
		{
			DBG2(DBG_IMC, "SWID tag ID generation by package manager");
			status = read_swid_tag_ids(this, file);
		}
		else
		{
			DBG2(DBG_IMC, "SWID tag generation by package manager");
			status = read_swid_tags(this, file);
		}
		pclose(file);
	}
	else if (!this->sw_id_only)
	{
		swima_record_t *target;
		enumerator_t *enumerator;
		chunk_t sw_id;

		enumerator = targets->create_enumerator(targets);
		while (enumerator->enumerate(enumerator, &target))
		{
			sw_id = target->get_sw_id(target, NULL);

			/* Assemble the SWID generator command */
			snprintf(command, BUF_LEN, "%s swid --software-id %.*s%s%s",
					 generator, sw_id.len, sw_id.ptr,
					 pretty ? " --pretty" : "", full ? " --full" : "");

			/* Open a pipe stream for reading the SWID generator output */
			file = popen(command, "r");
			if (!file)
			{
				DBG1(DBG_IMC, "failed to run swid_generator command");
				return NOT_SUPPORTED;
			}
			status = read_swid_tags(this, file);
			pclose(file);

			if (status != SUCCESS)
			{
				break;
			}
		}
		enumerator->destroy(enumerator);
	}

	return status;
}

static bool collect_tags(private_swima_collector_t *this, char *pathname,
						 swima_inventory_t *targets, bool is_swidtag_dir)
{
	char *rel_name, *abs_name, *suffix, *pos;
	chunk_t *swid_tag, sw_id, sw_locator;
	swima_record_t *sw_record;
	struct stat st;
	bool success = FALSE, skip, is_new_swidtag_dir;
	enumerator_t *enumerator;
	int i;

	enumerator = enumerator_create_directory(pathname);
	if (!enumerator)
	{
		DBG1(DBG_IMC, "directory '%s' can not be opened, %s",
					   pathname, strerror(errno));
		return FALSE;
	}

	while (enumerator->enumerate(enumerator, &rel_name, &abs_name, &st))
	{
		if (S_ISDIR(st.st_mode))
		{
			skip = FALSE;

			for (i = 0; i < countof(skip_directories); i++)
			{
				if (streq(abs_name, skip_directories[i]))
				{
					skip = TRUE;
					break;
				}
			}

			if (skip)
			{
				continue;
			}

			is_new_swidtag_dir =  streq(rel_name, "swidtag");
			if (is_new_swidtag_dir)
			{
				DBG2(DBG_IMC, "entering %s", pathname);
			}
			if (!collect_tags(this, abs_name, targets, is_swidtag_dir ||
													   is_new_swidtag_dir))
			{
				goto end;
			}
			if (is_new_swidtag_dir)
			{
				DBG2(DBG_IMC, "leaving %s", pathname);
			}
		}

		if (!is_swidtag_dir)
		{
			continue;
		}

		/* found a swidtag file? */
		suffix = strstr(rel_name, ".swidtag");
		if (!suffix)
		{
			continue;
		}

		/* load the swidtag file */
		swid_tag = chunk_map(abs_name, FALSE);
		if (!swid_tag)
		{
			DBG1(DBG_IMC, "  opening '%s' failed: %s", abs_name,
						  strerror(errno));
			goto end;
		}

		/* extract software identity from SWID tag */
		if (extract_sw_id(*swid_tag, &sw_id) != SUCCESS)
		{
			DBG1(DBG_IMC, "software id could not be extracted from SWID tag");
			chunk_unmap(swid_tag);
			goto end;
		}

		/* In case of a targeted request */
		if (targets->get_count(targets))
		{
			enumerator_t *target_enumerator;
			swima_record_t *target;
			bool match = FALSE;

			target_enumerator = targets->create_enumerator(targets);
			while (target_enumerator->enumerate(target_enumerator, &target))
			{
				if (chunk_equals(target->get_sw_id(target, NULL), sw_id))
				{
					match = TRUE;
					break;
				}
			}
			target_enumerator->destroy(target_enumerator);

			if (!match)
			{
				chunk_unmap(swid_tag);
				chunk_free(&sw_id);
				continue;
			}
		}
		DBG2(DBG_IMC, "  %s", rel_name);

		pos = strstr(pathname, "/swidtag");
		sw_locator = pos ? chunk_create(pathname, pos - pathname) : chunk_empty;
		sw_record = swima_record_create(0, sw_id, sw_locator);
		sw_record->set_source_id(sw_record, SOURCE_ID_COLLECTOR);
		if (!this->sw_id_only)
		{
			sw_record->set_record(sw_record, *swid_tag);
		}
		this->inventory->add(this->inventory, sw_record);
		chunk_unmap(swid_tag);
		chunk_free(&sw_id);
	}
	success = TRUE;

end:
	enumerator->destroy(enumerator);

	return success;
}

METHOD(swima_collector_t, collect, swima_inventory_t*,
	private_swima_collector_t *this, bool sw_id_only, swima_inventory_t *targets)
{
	char *directory, *generator;
	bool pretty, full;

	directory = lib->settings->get_str(lib->settings,
									"%s.plugins.imc-swima.swid_directory",
									 SWID_DIRECTORY, lib->ns);
	generator = lib->settings->get_str(lib->settings,
									"%s.plugins.imc-swima.swid_generator",
									 SWID_GENERATOR, lib->ns);
	pretty = lib->settings->get_bool(lib->settings,
									"%s.plugins.imc-swima.swid_pretty",
									 FALSE, lib->ns);
	full = lib->settings->get_bool(lib->settings,
									"%s.plugins.imc-swima.swid_full",
									 FALSE, lib->ns);
	/**
	 * Initialize collector
	 */
	this->sw_id_only = sw_id_only;
	this->inventory->destroy(this->inventory);
	this->inventory = swima_inventory_create();

	/**
	 * Source 1: Tags are generated by a package manager
	 */
	generate_tags(this, generator, targets, pretty, full);

	/**
	 * Source 2: Collect swidtag files by iteratively entering all
	 *           directories in the tree under the "directory" path.
	 */
	collect_tags(this, directory, targets, FALSE);

	return this->inventory;
}

METHOD(swima_collector_t, destroy, void,
	private_swima_collector_t *this)
{
	this->inventory->destroy(this->inventory);
	free(this);
}

/**
 * See header
 */
swima_collector_t *swima_collector_create(void)
{
	private_swima_collector_t *this;

	INIT(this,
		.public = {
			.collect = _collect,
			.destroy = _destroy,
		},
		.inventory = swima_inventory_create(),
	);

	return &this->public;
}
